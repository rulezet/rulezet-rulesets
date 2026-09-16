rule Win_Trojan_Bancos_712
{
strings:
	$a0 = { 4c0c3891d188ef8a2fcf4df325b70852599d34bb12c6c045e892217628f81f985d646b3e663c6a70e2896bbc5e97bab777effcf1076625ffd832d4e324f49ab65b }


condition:
	$a0
}