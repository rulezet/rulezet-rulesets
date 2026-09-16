rule Win_Trojan_Clonewar_1
{
strings:
	$a0 = { f700ba0001b440cd21b43ecd21ba1a01b90300b801 }


condition:
	$a0
}