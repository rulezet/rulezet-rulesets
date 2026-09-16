rule Win_Trojan_Taek_1
{
strings:
	$a0 = { b8afc9e84307b933072e8a1486e032d02e881446e2f3 }


condition:
	$a0
}