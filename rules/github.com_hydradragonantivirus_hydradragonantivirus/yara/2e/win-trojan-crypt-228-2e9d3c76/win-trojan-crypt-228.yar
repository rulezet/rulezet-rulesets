rule Win_Trojan_Crypt_228
{
strings:
	$a0 = { 558bece833f0ffff8be55dc3fc234a268fb9bb4df7a40c463f }

	$a1 = { 703667086bb8dbc6ce }


condition:
	$a0 and $a1
}