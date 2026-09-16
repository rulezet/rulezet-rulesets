rule Win_Trojan_Jerusalem_46
{
strings:
	$a0 = { f72e8b8d1100cd218cc8051000bc00 }


condition:
	$a0
}