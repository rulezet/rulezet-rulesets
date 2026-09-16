rule Win_Trojan_Philis_151
{
strings:
	$a0 = { 558bec83c4f0b8f06f4100e800003e28e80000de2ce8000027148bc000000000 }


condition:
	$a0
}