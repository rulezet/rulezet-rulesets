rule Win_Trojan_VGEN_419
{
strings:
	$a0 = { e80000cc5d81ed03002efe862400b42acd2181fa0a0c750eb40dcd2133d2b002b9feffcd25581e062efe8e240068cafa }


condition:
	$a0
}