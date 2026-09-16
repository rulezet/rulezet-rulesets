rule Win_Trojan_MPTI_1
{
strings:
	$a0 = { 5e50561e0e1ffaeb00c6440c8b8b847405fb1f83c62de8c8055e83c62f2e803c007402eb235646bf0001a5a55e }


condition:
	$a0
}