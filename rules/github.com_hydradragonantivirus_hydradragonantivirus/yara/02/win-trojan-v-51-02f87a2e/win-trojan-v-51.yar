rule Win_Trojan_V_51
{
strings:
	$a0 = { 0510000503008ed0bc20008cc801460ee8affffbff6e0c3d }


condition:
	$a0
}