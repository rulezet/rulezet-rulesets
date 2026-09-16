rule Win_Trojan_Monami_1
{
strings:
	$a0 = { 01b92304b44099e805017218c44cd28cc283e1e08bc2d0ec0accb801570806b703e80401b43e }


condition:
	$a0
}