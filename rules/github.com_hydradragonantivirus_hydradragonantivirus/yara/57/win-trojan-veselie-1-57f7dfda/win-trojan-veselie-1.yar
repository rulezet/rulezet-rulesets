rule Win_Trojan_Veselie_1
{
strings:
	$a0 = { 0e17bcfefffb2e8b16100181c2ce0283c2182e891608010e07b41acd210e1fba0a01b44eb90000cd217303e9dd002e }


condition:
	$a0
}