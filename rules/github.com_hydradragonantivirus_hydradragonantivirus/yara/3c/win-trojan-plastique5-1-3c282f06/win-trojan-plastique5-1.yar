rule Win_Trojan_Plastique5_1
{
strings:
	$a0 = { 80d8a11304b106d3e08ed833f68b44 }


condition:
	$a0
}