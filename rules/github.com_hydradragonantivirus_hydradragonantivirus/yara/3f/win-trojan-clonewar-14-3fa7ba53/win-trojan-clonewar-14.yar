rule Win_Trojan_Clonewar_14
{
strings:
	$a0 = { b43ccd21725193b90201ba0001b440cd21b43ecd21ba4401b90300b80143cd21c3bc0f048bdc }


condition:
	$a0
}