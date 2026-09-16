rule Win_Trojan_Featureless_1
{
strings:
	$a0 = { 9a272e1492ff1281a8121181ede2b5a113f9d810a551a856158192d012819a075414dc3023d1f9a5 }


condition:
	$a0
}