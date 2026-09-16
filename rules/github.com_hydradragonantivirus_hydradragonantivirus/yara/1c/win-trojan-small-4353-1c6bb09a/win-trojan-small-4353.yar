rule Win_Trojan_Small_4353
{
strings:
	$a0 = { 505f[0-255]505e81e800764000 }


condition:
	$a0
}