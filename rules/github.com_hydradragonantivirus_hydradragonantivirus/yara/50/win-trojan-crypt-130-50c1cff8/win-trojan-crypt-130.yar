rule Win_Trojan_Crypt_130
{
strings:
	$a0 = { 8124240000f0ff[0-25]81c2[0-30]8cc9[0-60]b900000050[0-40]2b05 }


condition:
	$a0
}