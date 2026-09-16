rule Win_Trojan_Abraxas_4
{
strings:
	$a0 = { 8ec026833e180240742a26c7061802400026a1200026 }


condition:
	$a0
}