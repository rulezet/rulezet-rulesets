rule Win_Trojan_Praios_1
{
strings:
	$a0 = { 42e8c20032e480f440baea03b90300cd21e98f0033c0350042e8aa0032e480f43fe8a90033 }


condition:
	$a0
}