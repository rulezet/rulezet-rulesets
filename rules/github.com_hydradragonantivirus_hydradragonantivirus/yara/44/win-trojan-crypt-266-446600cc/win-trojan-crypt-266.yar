rule Win_Trojan_Crypt_266
{
strings:
	$a0 = { a10022460033c1030dc021460003c82bd109d0391580204600742233d0baf9 }


condition:
	$a0
}