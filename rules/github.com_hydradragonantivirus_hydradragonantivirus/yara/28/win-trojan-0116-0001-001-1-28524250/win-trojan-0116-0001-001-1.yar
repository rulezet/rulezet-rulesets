rule Win_Trojan__0116_0001_001_1
{
strings:
	$a0 = { fd01b80042e82b008d96f801b90500b440cd21fe86ff015a59b80157cd21b43ecd2180beff0101 }


condition:
	$a0
}