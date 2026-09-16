rule Win_Trojan_KILTURD_1
{
strings:
	$a0 = { b80103cd137202eb32a0100424c0d0c0d0c0fec03c027223ba0100b80102b90100cd137216 }


condition:
	$a0
}