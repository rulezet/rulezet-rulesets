rule Win_Trojan_Mosdos_1
{
strings:
	$a0 = { e80300e9c30151bb4101508bc3050f00588a2f322e0301882f4333ff81fbe9037ee859c3ba00018b1e760153e8d7ff5bb9a802b440cd2153e8cbff5bc3 }


condition:
	$a0
}