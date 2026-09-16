rule Win_Trojan_VGEN_357
{
strings:
	$a0 = { b80009cd21b93200510e5b81c30002bf00018bc724f0c1e80429c38ec3be9f01b96400e88a0c0e1fb8003cba8e }


condition:
	$a0
}