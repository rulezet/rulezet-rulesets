rule Win_Trojan_Crypt_257
{
strings:
	$a0 = { 606bed01c6050317400014eb0599f078503aff0de92242006ae4fc5880dc }

	$a1 = { 44ab075c79585d3c433a }


condition:
	$a0 and $a1
}