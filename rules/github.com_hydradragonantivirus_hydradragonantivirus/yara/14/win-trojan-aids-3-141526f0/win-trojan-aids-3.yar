rule Win_Trojan_AIDS_3
{
strings:
	$a0 = { e581ec0202bfca050e57bf3e011e57 }


condition:
	$a0
}