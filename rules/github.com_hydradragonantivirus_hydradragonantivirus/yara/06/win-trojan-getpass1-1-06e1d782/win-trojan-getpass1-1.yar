rule Win_Trojan_GetPass1_1
{
strings:
	$a0 = { 167d00268916b9000e07beaf00bb0900 }


condition:
	$a0
}