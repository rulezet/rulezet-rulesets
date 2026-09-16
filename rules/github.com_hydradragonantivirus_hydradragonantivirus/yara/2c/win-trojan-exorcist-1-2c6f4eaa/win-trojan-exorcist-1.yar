rule Win_Trojan_Exorcist_1
{
strings:
	$a0 = { 408d960201b91001cd21b43ecd21813e00010e1f7504b4 }


condition:
	$a0
}