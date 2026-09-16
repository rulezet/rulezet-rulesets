rule Win_Trojan_DeepThough_1
{
strings:
	$a0 = { 084033c7066e080000c7066808c82ec7066a080000b8a80050b8480850e8fe1b59598b5e06 }


condition:
	$a0
}