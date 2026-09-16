rule Win_Dropper_Delf_2117
{
strings:
	$a0 = { 6a008bc325f0000000c1e8048b0485dc5040005083e3038b049dd0504000508bc6e815f7ffff50e887fdffff5e5bc3 }


condition:
	$a0
}