rule Win_Trojan_VGEN_793
{
strings:
	$a0 = { 8ed8be0000e82100b202e83100e82e00e82b00fec280fa0675f0be8300e80900bea701e80300eb28905052ac0a }


condition:
	$a0
}