rule Win_Trojan_Anti_5
{
strings:
	$a0 = { e8f800beb32be85300e82c038b4cfe83e10383c1032e890efe002ec706fe0001008344fe04e871 }


condition:
	$a0
}