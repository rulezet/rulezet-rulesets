rule Win_Trojan_Elvira_1
{
strings:
	$a0 = { 8b8464012ea300018aa466012e88260201f8e83701b42acd2180fe0a727480fe0c727252568db46d01fcac3c247413 }


condition:
	$a0
}