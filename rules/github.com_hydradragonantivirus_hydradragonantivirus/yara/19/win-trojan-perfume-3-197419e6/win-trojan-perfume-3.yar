rule Win_Trojan_Perfume_3
{
strings:
	$a0 = { bf0000f3a481ec000406bfba0057cb }


condition:
	$a0
}