rule Win_Trojan_Hafen_6
{
strings:
	$a0 = { 5e501e0681ee030133c08ed8a19a000e1f3d0010730afe843801e89300e817008ccb8b8c2e042b9c3004071f58 }


condition:
	$a0
}