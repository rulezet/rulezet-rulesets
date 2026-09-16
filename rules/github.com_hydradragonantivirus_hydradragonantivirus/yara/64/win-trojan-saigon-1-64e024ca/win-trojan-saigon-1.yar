rule Win_Trojan_Saigon_1
{
strings:
	$a0 = { 33c08ed88b1e6c04b8c8c7cd213bc374 }


condition:
	$a0
}