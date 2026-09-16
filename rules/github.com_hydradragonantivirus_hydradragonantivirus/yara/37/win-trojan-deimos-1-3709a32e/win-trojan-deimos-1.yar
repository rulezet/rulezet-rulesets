rule Win_Trojan_Deimos_1
{
strings:
	$a0 = { 03008d961702fec4cd21b002e85800b43fb915018d960301fec4cd21b801573e8b8e31023e }


condition:
	$a0
}