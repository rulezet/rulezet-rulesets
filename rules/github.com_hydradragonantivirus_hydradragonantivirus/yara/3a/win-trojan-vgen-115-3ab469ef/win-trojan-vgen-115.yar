rule Win_Trojan_VGEN_115
{
strings:
	$a0 = { c081c04d1d28db80cbf320f632ff80cf5720f628c980f182eb058247fbc00005604fd0c09033c1eb0707b657d2 }


condition:
	$a0
}