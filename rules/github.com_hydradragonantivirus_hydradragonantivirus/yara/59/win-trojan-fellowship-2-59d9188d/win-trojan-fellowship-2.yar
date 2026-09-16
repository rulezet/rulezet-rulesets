rule Win_Trojan_Fellowship_2
{
strings:
	$a0 = { fb341275248cc383c3102e011e2d00 }


condition:
	$a0
}