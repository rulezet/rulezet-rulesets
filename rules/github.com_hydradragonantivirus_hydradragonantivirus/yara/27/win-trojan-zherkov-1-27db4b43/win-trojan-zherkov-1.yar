rule Win_Trojan_Zherkov_1
{
strings:
	$a0 = { 51061ee800005e2e8a44f83c00740f83c61890b9d9062e }


condition:
	$a0
}