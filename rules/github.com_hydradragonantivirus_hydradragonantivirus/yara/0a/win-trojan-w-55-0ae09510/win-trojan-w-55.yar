rule Win_Trojan_W_55
{
strings:
	$a0 = { e8000300006681bd200a440050450f85a60100006681bd6c0a44000df00f8497 }


condition:
	$a0
}