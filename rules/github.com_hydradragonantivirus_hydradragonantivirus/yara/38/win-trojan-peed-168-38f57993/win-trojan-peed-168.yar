rule Win_Trojan_Peed_168
{
strings:
	$a0 = { 8d0567450300ba75e4280089c1710f5589e587022b55082b550cc9c208007601 }


condition:
	$a0
}