rule Win_Trojan_Ten_1
{
strings:
	$a0 = { 8d36f704bf0001b92000 }


condition:
	$a0
}