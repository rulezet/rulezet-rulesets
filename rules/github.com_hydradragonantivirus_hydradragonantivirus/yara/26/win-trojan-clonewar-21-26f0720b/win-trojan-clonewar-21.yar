rule Win_Trojan_Clonewar_21
{
strings:
	$a0 = { b90000b8003dcd21c3ba1a01b90000b43ccd21725f }


condition:
	$a0
}