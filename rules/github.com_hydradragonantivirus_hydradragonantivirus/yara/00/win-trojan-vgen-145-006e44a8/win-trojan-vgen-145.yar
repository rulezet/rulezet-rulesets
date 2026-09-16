rule Win_Trojan_VGEN_145
{
strings:
	$a0 = { 03029a00006a015589e5e822efbf22021e57e839f6e849fee86bf089ec5d31c09ad800030200005589e5e82a00 }


condition:
	$a0
}