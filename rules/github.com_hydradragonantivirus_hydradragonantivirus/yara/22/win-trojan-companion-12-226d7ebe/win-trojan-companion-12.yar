rule Win_Trojan_Companion_12
{
strings:
	$a0 = { 724b8bd8b9d700ba0001b440cd21b43ecd21ba1a01b90300b80143cd21c3b44acd21bf2c01be }


condition:
	$a0
}