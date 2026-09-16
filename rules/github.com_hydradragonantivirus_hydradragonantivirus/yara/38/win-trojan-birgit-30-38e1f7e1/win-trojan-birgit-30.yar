rule Win_Trojan_Birgit_30
{
strings:
	$a0 = { 2ec6867202e92e899e7302b90300eb005133c9e85600b002e84700b4408d96720259cd217210 }


condition:
	$a0
}