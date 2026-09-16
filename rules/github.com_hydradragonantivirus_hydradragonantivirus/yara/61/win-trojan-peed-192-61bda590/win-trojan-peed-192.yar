rule Win_Trojan_Peed_192
{
strings:
	$a0 = { eb2c68b0b900006800??bfff5af7da595289e689d45889f405 }


condition:
	$a0
}