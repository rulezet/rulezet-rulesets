rule Win_Trojan_Dikshev_29
{
strings:
	$a0 = { 4e87cecd217301c3be9e00bf370157acaa3c2e75fabe330166a55ab45bcd21720893b440ba370087d1ebd8 }


condition:
	$a0
}