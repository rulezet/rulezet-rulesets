rule Win_Trojan_Xcat_1
{
strings:
	$a0 = { b4dacd2181f90924751ae800005805????0e0e1f078bf0bf0001b90b00f3a4 }


condition:
	$a0
}