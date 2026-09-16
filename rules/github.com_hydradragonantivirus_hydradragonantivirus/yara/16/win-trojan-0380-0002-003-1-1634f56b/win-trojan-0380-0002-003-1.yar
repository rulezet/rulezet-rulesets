rule Win_Trojan__0380_0002_003_1
{
strings:
	$a0 = { b8004233c933d2cd01b440ba4305b90300cc5a59b80157cd01b43eccb801435a1f59cce9dffe }


condition:
	$a0
}