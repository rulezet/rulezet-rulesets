rule Win_Trojan_Companion_9
{
strings:
	$a0 = { 01b43ccd2172488bd8b9b200ba0001b440cd21b43ecd21ba1a01b90300b80143cd21c3b44acd }


condition:
	$a0
}