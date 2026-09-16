rule Win_Trojan_Kela_3
{
strings:
	$a0 = { b9d207b440e8beffc3b440b91800ba4908e8b2ffc3b43fba4908b91800e8a6ffc3f8e8d8ff }


condition:
	$a0
}