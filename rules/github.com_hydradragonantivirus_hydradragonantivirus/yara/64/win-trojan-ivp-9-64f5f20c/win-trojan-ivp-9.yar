rule Win_Trojan_IVP_9
{
strings:
	$a0 = { a42ec686bd02e92e899ebe02b90300eb005133c9e85600b002e84700b4408d96bd0259cd217210 }


condition:
	$a0
}