rule Win_Trojan_Popwin_14
{
strings:
	$a0 = { 33ffbeb05c001057575668305e0010e827f3ffff57575668a85d0010e81af3ffff8b358c40001083c4208d85e8fcffff50ffd68d85d0f6ffff50ffd633c05f5e5bc9c3 }


condition:
	$a0
}