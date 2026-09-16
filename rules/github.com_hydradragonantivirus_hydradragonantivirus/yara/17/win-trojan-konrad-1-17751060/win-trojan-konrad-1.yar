rule Win_Trojan_Konrad_1
{
strings:
	$a0 = { 5053518bdd81c3????b8????03c58a2f3e32ae????882f433bd875f2595b58c3 }


condition:
	$a0
}