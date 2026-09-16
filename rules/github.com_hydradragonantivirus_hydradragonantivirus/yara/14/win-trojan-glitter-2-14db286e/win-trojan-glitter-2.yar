rule Win_Trojan_Glitter_2
{
strings:
	$a0 = { e800005e83ee050e07c6441d908a5420b9c704bb2300301043e2fbc3eb03 }


condition:
	$a0
}