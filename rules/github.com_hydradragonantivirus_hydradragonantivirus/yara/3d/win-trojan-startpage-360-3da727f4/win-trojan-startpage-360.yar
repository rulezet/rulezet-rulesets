rule Win_Trojan_Startpage_360
{
strings:
	$a0 = { 6469616c2e657865000000005c746962732e6578650000005c63 }


condition:
	$a0
}