rule Win_Trojan_SillyORCE_16
{
strings:
	$a0 = { f3a466b81d004b0066268706840066abc380fc4b750fb8023dcd21930e1fb440b9320033d2ea }


condition:
	$a0
}