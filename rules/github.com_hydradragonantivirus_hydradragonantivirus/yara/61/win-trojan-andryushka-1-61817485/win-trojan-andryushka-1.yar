rule Win_Trojan_Andryushka_1
{
strings:
	$a0 = { 50e800005e83c60db92500310c464975fa }


condition:
	$a0
}