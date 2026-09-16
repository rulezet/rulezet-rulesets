rule Win_Trojan_Empire_1
{
strings:
	$a0 = { cd2193b440b9f800ba0001cd21b801578b4c168b5418cd21b43ecd21b8014332ed8a4c158d }


condition:
	$a0
}