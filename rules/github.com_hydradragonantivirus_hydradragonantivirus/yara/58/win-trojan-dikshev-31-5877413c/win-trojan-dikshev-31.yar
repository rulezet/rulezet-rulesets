rule Win_Trojan_Dikshev_31
{
strings:
	$a0 = { b44e87cecd217301c3be9e00bf390157acaa3c2e75fabe3501a5a55ab45bcd21720993b440ba39009087d1eb }


condition:
	$a0
}