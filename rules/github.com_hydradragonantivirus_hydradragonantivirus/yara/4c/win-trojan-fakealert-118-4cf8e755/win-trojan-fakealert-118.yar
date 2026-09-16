rule Win_Trojan_Fakealert_118
{
strings:
	$a0 = { 558bec6aff68e06157006880c1540064a10000000050648925 }

	$a1 = { 2353535550ff7424245653 }


condition:
	$a0 and $a1
}