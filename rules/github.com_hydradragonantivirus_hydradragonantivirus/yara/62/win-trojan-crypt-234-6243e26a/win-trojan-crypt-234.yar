rule Win_Trojan_Crypt_234
{
strings:
	$a0 = { 6801504000e801000000c3c31cb27a0cd87a74a65991b4fd8c89a3ec }


condition:
	$a0
}