rule Win_Trojan_Crypt_129
{
strings:
	$a0 = { b900000050[0-40]2b05[0-30]85c0[0-70]b9c3c3c3c3ebfa }


condition:
	$a0
}