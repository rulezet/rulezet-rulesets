rule Win_Trojan_LittleBrother_4
{
strings:
	$a0 = { 53501e063d004b7503e81000071f585b5a9d2eff2e }


condition:
	$a0
}