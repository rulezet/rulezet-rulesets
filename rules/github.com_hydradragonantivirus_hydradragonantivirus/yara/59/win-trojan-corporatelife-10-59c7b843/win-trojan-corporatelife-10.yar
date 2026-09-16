rule Win_Trojan_CorporateLife_10
{
strings:
	$a0 = { 90900e4545fb1ffb4d4d45ba3507454590be3e0145454580341990fb454645454a75f4904dfbfb904590fbfb90 }


condition:
	$a0
}