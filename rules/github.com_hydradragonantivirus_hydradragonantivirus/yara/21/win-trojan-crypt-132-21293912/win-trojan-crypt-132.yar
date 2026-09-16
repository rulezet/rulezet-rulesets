rule Win_Trojan_Crypt_132
{
strings:
	$a0 = { bafbffffff[0-60]250000ffff[0-10]890424[0-50]0fb701[0-10]6635adde[0-10]663d }


condition:
	$a0
}