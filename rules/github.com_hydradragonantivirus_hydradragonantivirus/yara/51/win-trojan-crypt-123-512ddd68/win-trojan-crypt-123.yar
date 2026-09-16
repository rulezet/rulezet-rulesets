rule Win_Trojan_Crypt_123
{
strings:
	$a0 = { 6869d60000e8c6fdffff6869d60000e8bcfdffff83c408e8a4ffffff84c074 }


condition:
	$a0
}