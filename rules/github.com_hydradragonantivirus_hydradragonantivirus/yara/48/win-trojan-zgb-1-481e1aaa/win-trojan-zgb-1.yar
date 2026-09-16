rule Win_Trojan_ZGB_1
{
strings:
	$a0 = { 1e1901b440cd21721c2efe064206b8004233c933d2cd21b4408b1e1901b90c00ba0607cd21e9b6 }


condition:
	$a0
}