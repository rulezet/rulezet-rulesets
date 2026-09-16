rule Win_Trojan_Gen_206
{
strings:
	$a0 = { 1e5731c031d252509acd059d00bf34261e57bf90131e57b823125031c050509a65059d0089 }


condition:
	$a0
}