rule Win_Trojan_Chapa_1
{
strings:
	$a0 = { 4d5a742b817c014b4d7424e87effb440b9bf010e1fba00020ee857ffe879ffb440b9bf01ba00bf }


condition:
	$a0
}