rule Win_Trojan_Himcrash_2
{
strings:
	$a0 = { 48696d43726173682077696c6c20776f726b20776974683a0a57696e646f7773204e }


condition:
	$a0
}