rule Win_Trojan_Evul_1
{
strings:
	$a0 = { 6d00ba0001cd21b43ecd21fe065601803e56010a74 }


condition:
	$a0
}