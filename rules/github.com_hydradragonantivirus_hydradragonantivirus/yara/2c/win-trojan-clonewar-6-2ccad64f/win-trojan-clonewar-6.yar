rule Win_Trojan_Clonewar_6
{
strings:
	$a0 = { b9e400ba0001b440cd21b43ecd21ba1901b90300b80143 }


condition:
	$a0
}