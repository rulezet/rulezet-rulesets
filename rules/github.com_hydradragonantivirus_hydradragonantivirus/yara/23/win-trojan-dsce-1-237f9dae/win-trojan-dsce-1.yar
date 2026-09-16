rule Win_Trojan_DSCE_1
{
strings:
	$a0 = { e83e023ddd4b7508e84902b84bdd9dcf3d004b740fe83c029d2eff2e1301b43ecd21ebf1 }


condition:
	$a0
}