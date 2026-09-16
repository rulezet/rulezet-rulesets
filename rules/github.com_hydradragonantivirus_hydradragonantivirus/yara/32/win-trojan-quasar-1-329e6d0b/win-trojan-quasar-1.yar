rule Win_Trojan_Quasar_1
{
strings:
	$a0 = { 0300baa201b440e83500b800425a33c9cd21b44033d2b9a601e82300b43ecd21b44fbaa501cd21 }


condition:
	$a0
}