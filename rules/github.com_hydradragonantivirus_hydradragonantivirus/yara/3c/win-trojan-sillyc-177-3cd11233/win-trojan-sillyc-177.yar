rule Win_Trojan_SillyC_177
{
strings:
	$a0 = { d8bb7204b8214389070e1f0e58b9101003c150a37701b9100003c1a340021fb41a33d2cd210e1fba4502b92000 }


condition:
	$a0
}