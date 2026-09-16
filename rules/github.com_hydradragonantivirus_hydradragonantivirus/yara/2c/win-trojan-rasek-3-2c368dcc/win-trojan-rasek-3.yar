rule Win_Trojan_Rasek_3
{
strings:
	$a0 = { e800005e81eeb3051e060e0e071f568bc605de0450b9b005565fac34abaae2fa }


condition:
	$a0
}