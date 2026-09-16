rule Win_Trojan_Heja_1
{
strings:
	$a0 = { 3dcd218bd81e5233d2b000e843ffb905000e1fba0f00 }


condition:
	$a0
}