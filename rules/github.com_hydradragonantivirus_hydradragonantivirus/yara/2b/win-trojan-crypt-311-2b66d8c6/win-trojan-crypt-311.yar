rule Win_Trojan_Crypt_311
{
strings:
	$a0 = { 807c2408010f85af01000060e8000000008b2c2483c404 }

	$a1 = { c6106148b6c7c74f0c93f09e7f7db04e00eb137aac46fa4bb7f3 }


condition:
	$a0 and $a1
}