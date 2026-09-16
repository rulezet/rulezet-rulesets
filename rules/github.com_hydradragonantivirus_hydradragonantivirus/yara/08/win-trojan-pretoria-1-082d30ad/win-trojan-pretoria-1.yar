rule Win_Trojan_Pretoria_1
{
strings:
	$a0 = { a5aa4b75f9c3a11f0150a11d01a3 }


condition:
	$a0
}