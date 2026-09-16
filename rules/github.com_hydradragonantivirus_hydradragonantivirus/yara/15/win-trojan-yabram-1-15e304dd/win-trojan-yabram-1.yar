rule Win_Trojan_Yabram_1
{
strings:
	$a0 = { 0100008bf581c670010000e833fbffff6681bd7001000050450f8516020000668b85860100 }


condition:
	$a0
}