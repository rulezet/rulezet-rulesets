rule Win_Trojan_Oeur_1
{
strings:
	$a0 = { 29fdb8ffffcd213daaaa7406e892fde8e7008cc98ed9a171058b1e6f05071f8cd903c10510005053cb33c08ed0 }


condition:
	$a0
}