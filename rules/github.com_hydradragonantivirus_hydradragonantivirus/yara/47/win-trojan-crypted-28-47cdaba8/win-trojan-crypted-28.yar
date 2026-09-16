rule Win_Trojan_Crypted_28
{
strings:
	$a0 = { 9090909090b800104000 }


condition:
	$a0
}