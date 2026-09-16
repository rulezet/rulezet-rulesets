rule Win_Dropper_Delf_472
{
strings:
	$a0 = { 686c3a4000a15056400050e8eafeffff50a15056400050e8eefeffff50e8f0feffff8bf0ba7c3a40008bc7e882eeffffba010000008bc7e85ef0ffff33db }


condition:
	$a0
}