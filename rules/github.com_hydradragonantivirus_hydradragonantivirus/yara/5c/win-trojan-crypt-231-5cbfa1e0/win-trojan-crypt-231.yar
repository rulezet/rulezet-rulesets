rule Win_Trojan_Crypt_231
{
strings:
	$a0 = { 9c60e8000000005db8070000002be88db591fbffff8a }


condition:
	$a0
}