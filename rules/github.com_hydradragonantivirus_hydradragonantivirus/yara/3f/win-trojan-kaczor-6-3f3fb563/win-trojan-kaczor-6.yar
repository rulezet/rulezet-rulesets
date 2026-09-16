rule Win_Trojan_Kaczor_6
{
strings:
	$a0 = { 802e2600802eff061300902e813e1300491175eb90 }


condition:
	$a0
}