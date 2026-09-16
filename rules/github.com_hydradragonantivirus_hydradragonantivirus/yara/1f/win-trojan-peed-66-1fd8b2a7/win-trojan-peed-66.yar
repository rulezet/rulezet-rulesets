rule Win_Trojan_Peed_66
{
strings:
	$a0 = { 29c9e830000000eb5f5589e5 }


condition:
	$a0
}