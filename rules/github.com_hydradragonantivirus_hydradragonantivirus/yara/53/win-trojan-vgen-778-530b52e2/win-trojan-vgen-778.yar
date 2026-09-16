rule Win_Trojan_VGEN_778
{
strings:
	$a0 = { 1503bfbcfab90700f3a5a12c008ed833f6ac0ac075fbac0ac075f6ad3d010075f0bff0fc33c9ac410ac0740d3c6172 }


condition:
	$a0
}