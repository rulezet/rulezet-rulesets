rule Win_Trojan_VGEN_243
{
strings:
	$a0 = { c2009a0d0044005589e5b802029acd02c20081ec0202e85cffbf35030e57e852febf3d030e57e84afebf47030e }


condition:
	$a0
}