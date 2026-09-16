rule Win_Trojan_Replico_1
{
strings:
	$a0 = { 2ec6868b02e92e899e8c02b90300eb005133c9e85600b002e84700b4408d968b0259cd217210 }


condition:
	$a0
}