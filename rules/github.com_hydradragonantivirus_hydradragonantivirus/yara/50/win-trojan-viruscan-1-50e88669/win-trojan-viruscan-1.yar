rule Win_Trojan_Viruscan_1
{
strings:
	$a0 = { 91088ed8be0000e81b00b200e82b00e82800e82500fec280fa0475f0be1900e80300eb28905052ac0ac0740b86d080 }


condition:
	$a0
}