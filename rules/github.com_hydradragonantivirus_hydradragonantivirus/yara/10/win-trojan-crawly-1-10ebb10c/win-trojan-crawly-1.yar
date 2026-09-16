rule Win_Trojan_Crawly_1
{
strings:
	$a0 = { e0009a000052005589e581ec0002c606e41e00c606d21e55c606d31e6ac606d41e66c606d51e24c606d61e46c6 }


condition:
	$a0
}