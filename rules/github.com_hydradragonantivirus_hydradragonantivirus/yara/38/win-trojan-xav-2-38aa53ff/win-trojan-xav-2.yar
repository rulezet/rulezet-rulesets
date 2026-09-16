rule Win_Trojan_Xav_2
{
strings:
	$a0 = { b8554bcd213d45527452b82135cd21 }


condition:
	$a0
}