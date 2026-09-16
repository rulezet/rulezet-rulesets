rule Win_Trojan_Crypt_204
{
strings:
	$a0 = { 2bc0740dd3580df3c97809fdd85238f9cd6057bf1008222481c7723ce7e303df5f61e9b7edffff81f6d9 }


condition:
	$a0
}