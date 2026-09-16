rule Win_Trojan_Birgit_31
{
strings:
	$a0 = { 2ec686c402e92e899ec502b90300eb005133c9e85600b002e84700b4408d96c40259cd217210 }


condition:
	$a0
}