rule Win_Trojan_Small_4357
{
strings:
	$a0 = { 505b50[0-255]81e800764000f7d0ffc0 }


condition:
	$a0
}