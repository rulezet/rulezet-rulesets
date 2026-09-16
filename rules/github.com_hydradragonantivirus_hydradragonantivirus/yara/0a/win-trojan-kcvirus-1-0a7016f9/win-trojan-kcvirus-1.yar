rule Win_Trojan_KcVirus_1
{
strings:
	$a0 = { 03c1a38100512e8b1e3d01b90500b440cd2159721e51e8fdfe597217b440cd2172110e1fba00 }


condition:
	$a0
}