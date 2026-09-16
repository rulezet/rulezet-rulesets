rule Win_Trojan_Trivial_208
{
strings:
	$a0 = { cd21b43ecd21cd202a2e434f4d00 }


condition:
	$a0
}