rule libmpdvdkit2_css_pp_perm_challenge__8_byt_30_
{
strings:
	$a0 = { 010300070502090604080601090308050704000204000305070208060109 }

condition:
	$a0
}