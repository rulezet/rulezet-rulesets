rule Win_Trojan_VGEN_481
{
strings:
	$a0 = { 1400f3a4e8f3010e0e071fb41a8d96d704cd21e8c900b41aba8000cd21b8002acd2180fe06 }


condition:
	$a0
}