rule Win_Dropper_Delf_585
{
strings:
	$a0 = { 8b953cffffff58e802afffff8b8540ffffffe8efb0ffff50688caa40006a00e802f6ffff }


condition:
	$a0
}