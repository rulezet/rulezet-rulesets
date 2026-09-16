rule Win_Trojan_EvilEmpire_1
{
strings:
	$a0 = { 4c80fc02754731c08ed8803e6c0416 }


condition:
	$a0
}