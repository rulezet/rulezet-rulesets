rule Win_Trojan_PolyVirus_1
{
strings:
	$a0 = { 0e1fb90300cd2172deb8004233c933d2cd21b4400e1fba8b005b03d3b9030053be850003f38b }


condition:
	$a0
}