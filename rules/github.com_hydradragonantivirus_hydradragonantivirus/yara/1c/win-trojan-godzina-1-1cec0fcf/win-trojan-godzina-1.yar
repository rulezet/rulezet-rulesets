rule Win_Trojan_Godzina_1
{
strings:
	$a0 = { a60003d92e8a0751b104d2c82e880759e2ed0e1f }


condition:
	$a0
}