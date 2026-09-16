rule Win_Trojan_L_48
{
strings:
	$a0 = { 8bec80fc0f740580fc3d75062e803e4f01019c55ff76062e }


condition:
	$a0
}