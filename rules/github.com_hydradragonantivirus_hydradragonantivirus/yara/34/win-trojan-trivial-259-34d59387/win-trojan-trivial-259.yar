rule Win_Trojan_Trivial_259
{
strings:
	$a0 = { ba9e00cd21b92c008d160001b440cd21b43ecd21b44f }


condition:
	$a0
}