rule Win_Trojan_Mobius_2
{
strings:
	$a0 = { 028dbee901f3a4b4408bd581c20001b9e700cd217214 }


condition:
	$a0
}