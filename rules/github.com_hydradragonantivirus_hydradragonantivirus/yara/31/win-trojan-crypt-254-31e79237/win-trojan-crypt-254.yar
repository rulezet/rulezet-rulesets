rule Win_Trojan_Crypt_254
{
strings:
	$a0 = { b8888d4900ffe0005e00000800094c07 }

	$a1 = { 6669726577616c6c20616464[0-33]5c7379736d6f642e657865 }


condition:
	$a0 and $a1
}