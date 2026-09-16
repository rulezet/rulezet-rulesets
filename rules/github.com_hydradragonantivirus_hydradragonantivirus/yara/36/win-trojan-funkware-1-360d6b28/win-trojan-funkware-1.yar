rule Win_Trojan_Funkware_1
{
strings:
	$a0 = { 0356fc81c61101bf0001a5a55e8d941a01b41acd21 }


condition:
	$a0
}