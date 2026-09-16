rule Win_Trojan__0110_0003_000_1
{
strings:
	$a0 = { c18ec0b9d808ba0000e86a005bb440cd210e1f33c933d2b80042cd21b440b90400ba0200cd }


condition:
	$a0
}