rule Win_Trojan__0117_0001_001_1
{
strings:
	$a0 = { b80042e82b008d96fa01b90500b440cd21fe8601025a59b80157cd21b43ecd2180be010201 }


condition:
	$a0
}