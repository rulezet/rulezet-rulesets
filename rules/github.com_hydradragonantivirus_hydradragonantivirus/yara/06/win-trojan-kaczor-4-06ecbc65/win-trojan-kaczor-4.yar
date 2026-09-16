rule Win_Trojan_Kaczor_4
{
strings:
	$a0 = { 2700042eff061400902e813e14004a1175eb90 }


condition:
	$a0
}