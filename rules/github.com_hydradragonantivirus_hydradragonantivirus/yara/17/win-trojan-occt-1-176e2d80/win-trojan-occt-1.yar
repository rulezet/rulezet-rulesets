rule Win_Trojan_OCCT_1
{
strings:
	$a0 = { ffb98403b440cd211f7219b80042b90000ba0000cd21 }


condition:
	$a0
}