rule Win_Dropper_Delf_756
{
strings:
	$a0 = { e856a7ffffe8c1a1ffffb854a84000e867a7ffffe8b2a1ffff8bc3e8d7a0ffff6a0a6824854000e81bc7ffff }


condition:
	$a0
}