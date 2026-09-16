rule Win_Trojan_Crypted_36
{
strings:
	$a0 = { 60909090909067e8000000009090 }


condition:
	$a0
}