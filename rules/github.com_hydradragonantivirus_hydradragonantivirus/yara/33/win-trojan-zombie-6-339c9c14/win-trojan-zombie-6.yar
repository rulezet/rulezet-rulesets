rule Win_Trojan_Zombie_6
{
strings:
	$a0 = { bb0000e4402507008bd080c288e4400ac074fa8ae0eeec2ac498d1c88d9747022bd0e8020061c3be0001b96400ffd2 }


condition:
	$a0
}