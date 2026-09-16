rule Win_Trojan_Ailbone_2
{
strings:
	$a0 = { 5ec08ed0bc007c8bf45007501ffbfcbf0006b90001f2a5ea1d060000bebe07b304803c80740e803c00751c83c6 }


condition:
	$a0
}