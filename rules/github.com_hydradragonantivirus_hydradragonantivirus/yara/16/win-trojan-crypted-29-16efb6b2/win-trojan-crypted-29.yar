rule Win_Trojan_Crypted_29
{
strings:
	$a0 = { 9090906090 }


condition:
	$a0
}