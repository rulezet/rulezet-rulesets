rule Win_Dropper_Delf_614
{
strings:
	$a0 = { 6a008d442404506a1e68544014136af5e886e0ffff50e8a0e0ffff6a008d442404506a0268c42f14136af5e86be0ffff50e885e0ffff }


condition:
	$a0
}