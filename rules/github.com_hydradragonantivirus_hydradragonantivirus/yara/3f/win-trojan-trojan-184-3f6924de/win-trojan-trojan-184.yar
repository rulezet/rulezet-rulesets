rule Win_Trojan_Trojan_184
{
strings:
	$a0 = { 8bf0eb0990bf00008bec8b03c356b9040081c6ca01 }


condition:
	$a0
}