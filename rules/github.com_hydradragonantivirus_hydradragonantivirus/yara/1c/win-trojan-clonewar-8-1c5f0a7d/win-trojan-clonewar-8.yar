rule Win_Trojan_Clonewar_8
{
strings:
	$a0 = { ba1a0133c9b8003dcd21c3ba1a0133c9b43ccd2172538bd8b9eb00ba0001b440cd21b43ecd21 }


condition:
	$a0
}