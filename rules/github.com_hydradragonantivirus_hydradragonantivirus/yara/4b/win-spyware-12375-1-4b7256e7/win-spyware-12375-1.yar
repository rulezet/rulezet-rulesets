rule Win_Spyware_12375_1
{
strings:
	$a0 = { 558bec83c4f05356b82c774e00e81d0057b868587c4e00e81d0062d08bf068587c4e006aff6a00e81d0059d8 }


condition:
	$a0
}