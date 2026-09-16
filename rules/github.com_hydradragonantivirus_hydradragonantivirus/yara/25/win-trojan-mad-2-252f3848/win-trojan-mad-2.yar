rule Win_Trojan_MAD_2
{
strings:
	$a0 = { 5c20dcaa152cba2c119ae22f2d152cba2ae32b2af73d15233048122a2a87ab17652b152cba137f6e }


condition:
	$a0
}