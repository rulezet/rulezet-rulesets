rule Win_Trojan_SouthAfrican1_1
{
strings:
	$a0 = { ecc746100001e80000582dd700b1 }


condition:
	$a0
}