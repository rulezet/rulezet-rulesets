rule Win_Trojan_Birgit_29
{
strings:
	$a0 = { a42ec6867002e92e899e7102b90300eb005133c9e85600b002e84700b4408d96700259cd217210 }


condition:
	$a0
}