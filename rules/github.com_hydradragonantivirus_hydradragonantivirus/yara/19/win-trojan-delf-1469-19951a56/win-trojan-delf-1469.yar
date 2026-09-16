rule Win_Trojan_Delf_1469
{
strings:
	$a0 = { 33c080fb010f8565020000833dec804600640f9cc280ea0172407550baa86945008b45f4e8b7e7faff85c07e04b001eb3b }


condition:
	$a0
}