rule Win_Trojan_Trojan_185
{
strings:
	$a0 = { 8bf0eb0990bf00008bec8b03c356b9040081c66d01 }


condition:
	$a0
}