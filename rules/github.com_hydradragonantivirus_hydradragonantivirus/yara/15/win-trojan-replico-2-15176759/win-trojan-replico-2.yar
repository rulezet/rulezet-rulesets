rule Win_Trojan_Replico_2
{
strings:
	$a0 = { 2ec6869202e92e899e9302b90300eb005133c9e85600b002e84700b4408d96920259cd217210 }


condition:
	$a0
}