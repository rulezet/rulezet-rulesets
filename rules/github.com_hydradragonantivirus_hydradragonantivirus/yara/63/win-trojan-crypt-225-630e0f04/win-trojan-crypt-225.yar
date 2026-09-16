rule Win_Trojan_Crypt_225
{
strings:
	$a0 = { e81e000000660f6e06660f7ec083c60283c602f9722d0f6ec00f7e }

	$a1 = { 3030303030303135 }


condition:
	$a0 and $a1
}