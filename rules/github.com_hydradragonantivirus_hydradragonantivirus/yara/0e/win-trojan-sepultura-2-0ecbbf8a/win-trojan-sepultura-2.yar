rule Win_Trojan_Sepultura_2
{
strings:
	$a0 = { 09006a00e2fc61b84202cd21e800005e81ee1000bf4202073d4202741db9f20056f3a45e061fb82135cd218c061c03 }


condition:
	$a0
}