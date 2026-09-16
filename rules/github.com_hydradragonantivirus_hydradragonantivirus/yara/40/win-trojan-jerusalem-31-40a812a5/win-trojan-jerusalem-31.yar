rule Win_Trojan_Jerusalem_31
{
strings:
	$a0 = { b54e0ec6c45b25cfb00c1702f27d00e8010006591f4005c5c64a0ac2c6c002e80b000b61d04811bebe4d1ac3bc5b8b }


condition:
	$a0
}