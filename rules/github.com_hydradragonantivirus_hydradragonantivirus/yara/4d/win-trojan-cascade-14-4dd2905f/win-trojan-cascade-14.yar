rule Win_Trojan_Cascade_14
{
strings:
	$a0 = { 012ef6872a0101740f8db74d01b982063134310c46e2f9 }


condition:
	$a0
}