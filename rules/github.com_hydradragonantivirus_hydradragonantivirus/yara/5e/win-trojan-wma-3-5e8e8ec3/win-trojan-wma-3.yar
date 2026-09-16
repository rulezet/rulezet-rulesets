rule Win_Trojan_WMA_3
{
strings:
	$a0 = { 862400b42acd2181fa0a0c750eb40dcd2133d2b002b9feffcd25581e062efe8e240068cafa58 }


condition:
	$a0
}