rule Win_Dropper_Delf_839
{
strings:
	$a0 = { 6a008d442404506a1e685c5040006af5e876e0ffff50e890e0ffff6a008d442404506a0268d42f40006af5e85be0ffff50e875e0ffff5ac3 }


condition:
	$a0
}