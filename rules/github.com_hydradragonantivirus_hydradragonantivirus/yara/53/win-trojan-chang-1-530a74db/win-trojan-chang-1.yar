rule Win_Trojan_Chang_1
{
strings:
	$a0 = { 9c3d004b7503e806009d2eff2e50015053515257561e06 }


condition:
	$a0
}