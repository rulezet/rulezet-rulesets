rule Win_Trojan_FreddySoft_1
{
strings:
	$a0 = { 23b07ec8ab74f0aea0f0affcf0d8d5f0ab3cf0aec8f0aff4f0d8c9f0f67cb8f5 }


condition:
	$a0
}