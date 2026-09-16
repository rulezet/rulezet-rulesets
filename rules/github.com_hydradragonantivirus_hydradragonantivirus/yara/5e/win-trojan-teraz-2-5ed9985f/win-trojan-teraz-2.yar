rule Win_Trojan_Teraz_2
{
strings:
	$a0 = { 742680fc4e741180fc4f740c80fc11740f80fc1274 }


condition:
	$a0
}