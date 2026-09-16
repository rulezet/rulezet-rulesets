rule Win_Trojan_ZzTop_1
{
strings:
	$a0 = { 3e86010c7406fe068601eb09ff068301c6068601018cc8 }


condition:
	$a0
}