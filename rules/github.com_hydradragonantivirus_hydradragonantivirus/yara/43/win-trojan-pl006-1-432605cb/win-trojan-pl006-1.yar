rule Win_Trojan_PL006_1
{
strings:
	$a0 = { 0183c3018e078cc03d504c75f48e47028cc03d2a2e75ea8e47048cc03d636f75e00783c302891e1301bb0a0129 }


condition:
	$a0
}