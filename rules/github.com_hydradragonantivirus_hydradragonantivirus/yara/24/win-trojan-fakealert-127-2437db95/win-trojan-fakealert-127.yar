rule Win_Trojan_Fakealert_127
{
strings:
	$a0 = { 681bb2eb7568ca7336d8e8d80000007200ed0000002c00005b174300002e00a461 }


condition:
	$a0
}