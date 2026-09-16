rule Win_Trojan_Crypt_165
{
strings:
	$a0 = { 43555252454e545f55534552 }

	$a1 = { 5bc36e746f736b726e6c2e657865 }

	$a2 = { 5f2e657865 }


condition:
	$a0 and $a1 and $a2
}