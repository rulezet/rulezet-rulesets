rule Win_Trojan_Zbot_1345
{
strings:
	$a0 = { 8b45088b4d0c33??83[2]d3??23[1-2]8be55dc20800 }


condition:
	$a0
}