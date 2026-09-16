rule Win_Trojan_Rogue_3
{
strings:
	$a0 = { f3068bf70e1f8cc3b4001e07b9f00690fcac32c4aafec4e2f8 }


condition:
	$a0
}