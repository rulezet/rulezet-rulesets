rule Win_Trojan_Lupus_2
{
strings:
	$a0 = { 66b86c6c6548cd21663d4543694e0f858dfd }


condition:
	$a0
}