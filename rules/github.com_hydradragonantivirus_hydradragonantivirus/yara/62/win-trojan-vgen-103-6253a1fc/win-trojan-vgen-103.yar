rule Win_Trojan_VGEN_103
{
strings:
	$a0 = { 4679f72bc1782d01bf256d9f2cea086f932e285c21c08828db64eea2e14b1c59a28e3afc476189655b07753db831be }


condition:
	$a0
}