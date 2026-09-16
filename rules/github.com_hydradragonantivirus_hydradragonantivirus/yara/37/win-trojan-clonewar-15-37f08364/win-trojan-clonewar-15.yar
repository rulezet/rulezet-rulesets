rule Win_Trojan_Clonewar_15
{
strings:
	$a0 = { d8b90501ba0001b440cd21b43ecd21ba2801b90300b801 }


condition:
	$a0
}