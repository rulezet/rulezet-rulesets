rule Win_Trojan_Companion_14
{
strings:
	$a0 = { b8003dcd21c3ba1a01b43ccd21724b8bd8b9df00ba0001b440cd21b43ecd21ba1a01b90300 }


condition:
	$a0
}