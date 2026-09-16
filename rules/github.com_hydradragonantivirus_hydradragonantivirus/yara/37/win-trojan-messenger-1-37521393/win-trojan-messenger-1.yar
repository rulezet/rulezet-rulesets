rule Win_Trojan_Messenger_1
{
strings:
	$a0 = { c686dd02e92e899ede02b90300eb005133c9e85600b002e84700b4408d96dd0259cd217210 }


condition:
	$a0
}