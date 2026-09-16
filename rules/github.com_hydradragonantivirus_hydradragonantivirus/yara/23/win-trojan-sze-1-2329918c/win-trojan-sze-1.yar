rule Win_Trojan_SZE_1
{
strings:
	$a0 = { b90300b440cd217214b002e86fff8b160100b93a011e0e1fb440cd211fb43ecd21c3 }


condition:
	$a0
}