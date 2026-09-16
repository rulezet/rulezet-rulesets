rule Win_Trojan_Bubonic_1
{
strings:
	$a0 = { e800005e83ee03cd6b3c707503e98c00b90a00bb0400b43ecd218bd9e2f88cddb452cd21268b47fe2e898485088ed8c6 }


condition:
	$a0
}