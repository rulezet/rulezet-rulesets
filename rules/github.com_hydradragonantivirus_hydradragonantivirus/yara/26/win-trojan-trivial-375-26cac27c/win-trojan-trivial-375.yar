rule Win_Trojan_Trivial_375
{
strings:
	$a0 = { e3b409ba3601cd21cd20633a5c2a2e636f6d00202d }


condition:
	$a0
}