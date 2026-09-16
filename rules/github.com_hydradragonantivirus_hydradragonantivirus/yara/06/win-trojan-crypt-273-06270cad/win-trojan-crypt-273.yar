rule Win_Trojan_Crypt_273
{
strings:
	$a0 = { 558bec03fe81df6efced7903d74281c61b62c7ae81e6058eb8040f8c81fcffff0f8d7bfcffff10801880 }


condition:
	$a0
}