rule Win_Trojan_VGEN_680
{
strings:
	$a0 = { 1f0e07e84b018c0ee2018c0ee4018c0eda018c0ee001c7060300feebfa8c16e6018926e8010e17bc842bb80202500e }


condition:
	$a0
}