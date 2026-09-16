rule Win_Trojan_Autorun_487
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d737663737273732e657865 }


condition:
	$a0
}