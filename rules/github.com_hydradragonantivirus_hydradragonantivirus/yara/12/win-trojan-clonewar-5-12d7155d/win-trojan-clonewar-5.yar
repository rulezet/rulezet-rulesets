rule Win_Trojan_Clonewar_5
{
strings:
	$a0 = { de0133c9b8003dcd21c3bade0133c9b43ccd2172538bd8b9dc00ba0001b440cd21b43ecd21 }


condition:
	$a0
}