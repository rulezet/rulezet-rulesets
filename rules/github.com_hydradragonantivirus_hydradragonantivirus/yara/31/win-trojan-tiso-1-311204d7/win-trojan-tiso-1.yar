rule Win_Trojan_Tiso_1
{
strings:
	$a0 = { 8ed0bc007c161fa113044848a31304b106d3e08ec02ea3347cba8000b9020033dbb80302cd13730633c0 }


condition:
	$a0
}