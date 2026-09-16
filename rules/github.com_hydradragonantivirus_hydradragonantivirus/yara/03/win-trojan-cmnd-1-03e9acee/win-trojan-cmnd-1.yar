rule Win_Trojan_Cmnd_1
{
strings:
	$a0 = { c6c009adfec4740497a5ebf75eba0001b90010038c1001b440cd2133c9b440cd21595ab80157cd }


condition:
	$a0
}