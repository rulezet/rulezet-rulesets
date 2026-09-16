rule Win_Trojan_Replico_3
{
strings:
	$a0 = { 2ec686b502e92e899eb602b90300eb005133c9e85600b002e84700b4408d96b50259cd217210 }


condition:
	$a0
}