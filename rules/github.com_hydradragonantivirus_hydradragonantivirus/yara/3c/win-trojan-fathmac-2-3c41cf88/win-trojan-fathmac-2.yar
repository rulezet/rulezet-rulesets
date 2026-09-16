rule Win_Trojan_FathMac_2
{
strings:
	$a0 = { 88c083c200b9b30681e9220180c500268a0289d289ff345583e90083eb0026880283c30046e2e8 }


condition:
	$a0
}