rule Win_Trojan_Intruder_7
{
strings:
	$a0 = { b002a2fd00e81000740d32c0a2af00fec0a2fd00e8 }


condition:
	$a0
}