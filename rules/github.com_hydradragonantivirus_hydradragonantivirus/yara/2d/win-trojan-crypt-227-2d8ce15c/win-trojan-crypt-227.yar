rule Win_Trojan_Crypt_227
{
strings:
	$a0 = { 68ce714500e8f6100000ec74786878647c6c405c544c4878 }

	$a1 = { 5c046bb35c61657243a369466574455c0879 }


condition:
	$a0 and $a1
}