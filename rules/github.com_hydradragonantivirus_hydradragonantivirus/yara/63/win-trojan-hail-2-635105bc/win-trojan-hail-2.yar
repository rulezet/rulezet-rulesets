rule Win_Trojan_Hail_2
{
strings:
	$a0 = { fc368b2d444481ed03000e0e1f078dbe2900e8dcffb9b0bf91cd213d6b6b745f0e078cc048501f33ff803d59766d83 }


condition:
	$a0
}