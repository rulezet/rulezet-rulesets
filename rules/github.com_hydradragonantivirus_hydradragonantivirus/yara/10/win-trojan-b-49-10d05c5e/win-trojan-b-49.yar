rule Win_Trojan_B_49
{
strings:
	$a0 = { c08ed8a1130448a31304bb4000f7e32d10008ec050be007cbf0001b90002fcf3a4b8330150cb }


condition:
	$a0
}