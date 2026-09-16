rule Win_Trojan_Peed_44
{
strings:
	$a0 = { e8170000005dc30f31c38af2b92e190000301002d68d4001e2 }


condition:
	$a0
}