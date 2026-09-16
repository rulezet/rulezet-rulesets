rule Win_Trojan_Troj_1
{
strings:
	$a0 = { 5d81ed9401b404cd1a2e3a969a0272572e3ab69b0272502e3a8e9c02724933db8ac3e67032 }


condition:
	$a0
}