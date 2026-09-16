rule Win_Trojan_Crypt_168
{
strings:
	$a0 = { e8??f?ffff680401000068??3140006a00ff1544304000 }


condition:
	$a0
}