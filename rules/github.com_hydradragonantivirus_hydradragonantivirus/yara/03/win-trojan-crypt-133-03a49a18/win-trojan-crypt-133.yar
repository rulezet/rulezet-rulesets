rule Win_Trojan_Crypt_133
{
strings:
	$a0 = { baffffffff[0-30]81c2[0-60]0fb701[0-10]66353412[0-10]663d }


condition:
	$a0
}