rule Win_Trojan_SZE_2
{
strings:
	$a0 = { ba0500b90300b440cd217214b002e85aff8b160100b95f011e0e1fb440cd211fb43ecd21c3 }


condition:
	$a0
}