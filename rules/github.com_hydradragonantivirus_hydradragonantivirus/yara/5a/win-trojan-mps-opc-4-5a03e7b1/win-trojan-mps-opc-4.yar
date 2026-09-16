rule Win_Trojan_MPS_OPC_4
{
strings:
	$a0 = { 2c008ed833ff8b05470bc075f983c7038bd7c33d00 }


condition:
	$a0
}