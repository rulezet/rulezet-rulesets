rule Win_Trojan_VGEN_381
{
strings:
	$a0 = { e839000001f0ff4d524549e9dc032049dcff31f6e81300e806009ce80c009dc39c9a67147402c3b003cf565183c643b9 }


condition:
	$a0
}