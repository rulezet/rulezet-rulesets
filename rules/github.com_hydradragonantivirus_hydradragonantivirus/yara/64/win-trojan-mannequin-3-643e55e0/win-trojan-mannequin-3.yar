rule Win_Trojan_Mannequin_3
{
strings:
	$a0 = { c6b440ba0000b90a0390cd213bc1 }


condition:
	$a0
}