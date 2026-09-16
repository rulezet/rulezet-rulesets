rule Win_Trojan_Clonewar_18
{
strings:
	$a0 = { b92302ba0001b440cd21b43ecd21ba5702b90300b80143 }


condition:
	$a0
}