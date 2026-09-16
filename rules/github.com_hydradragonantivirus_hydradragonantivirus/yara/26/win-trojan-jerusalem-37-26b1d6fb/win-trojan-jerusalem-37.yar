rule Win_Trojan_Jerusalem_37
{
strings:
	$a0 = { be000183c6122ef6142ef61c46e2f78bbf040fff2d000547002d0005aa0ab302cc0f3b65740a2d7f3d990a0073 }


condition:
	$a0
}