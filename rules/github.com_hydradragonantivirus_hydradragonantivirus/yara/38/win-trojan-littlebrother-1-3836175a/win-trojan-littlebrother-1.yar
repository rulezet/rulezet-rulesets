rule Win_Trojan_LittleBrother_1
{
strings:
	$a0 = { 5253501e063d004b7503e8100007 }


condition:
	$a0
}