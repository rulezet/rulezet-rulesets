rule Win_Dropper_Delf_828
{
strings:
	$a0 = { 6a0068800000006a026a006a0268000000408d45e88bd3e84fb9ffff8b4de88d45ec8b55f4e825baffff8b45ece81dbbffff50e8b7c6ffff }


condition:
	$a0
}