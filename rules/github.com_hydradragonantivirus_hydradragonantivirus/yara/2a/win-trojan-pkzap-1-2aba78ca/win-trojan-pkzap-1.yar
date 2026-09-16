rule Win_Trojan_PKZap_1
{
strings:
	$a0 = { 998bc88bdaa1720131d29a5007eb02a380019a4b027d0230e4a37801bf98021e57bfed220e }


condition:
	$a0
}