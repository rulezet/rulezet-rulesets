rule Win_Trojan_BlackAdder_1
{
strings:
	$a0 = { e800008bf45c83c426b9e501ba2e00bb080e58d1c2d1cb03d3d1fa83c20333c25044444983f90075 }


condition:
	$a0
}