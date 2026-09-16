rule Win_Trojan_Trojan_81
{
strings:
	$a0 = { 1e25000bdb7413b90080f3a5050010 }


condition:
	$a0
}