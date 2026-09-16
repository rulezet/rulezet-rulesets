rule Win_Trojan_Duke_5
{
strings:
	$a0 = { 652f534d465d9a000008019a2e0f06005589e531c09a30050801bfaa1a1e57bf00000e5731 }


condition:
	$a0
}