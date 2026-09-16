rule Win_Trojan_Havar_2
{
strings:
	$a0 = { e856f0ffffe811f1ffff8d45fc506a016a008d4df4ba24000000b8783b4000e8e3eeffff8b45f4e8e3e0ffff506802000080e8bce4ffff }


condition:
	$a0
}