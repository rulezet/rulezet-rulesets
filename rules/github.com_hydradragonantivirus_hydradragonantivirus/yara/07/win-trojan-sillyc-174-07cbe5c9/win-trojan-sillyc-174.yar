rule Win_Trojan_SillyC_174
{
strings:
	$a0 = { 8ed8bb7204b8214389070e1f0e58b9101003c150a37601b9100003c1a33e021fb41a33d2cd210e1fba4302b92000 }


condition:
	$a0
}