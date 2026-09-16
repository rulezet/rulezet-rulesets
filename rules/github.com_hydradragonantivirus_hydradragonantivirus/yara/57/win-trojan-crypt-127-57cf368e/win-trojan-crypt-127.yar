rule Win_Trojan_Crypt_127
{
strings:
	$a0 = { 81e20000f0ff[0-10]81c2[0-70]85c0[0-20]ffe0 }


condition:
	$a0
}