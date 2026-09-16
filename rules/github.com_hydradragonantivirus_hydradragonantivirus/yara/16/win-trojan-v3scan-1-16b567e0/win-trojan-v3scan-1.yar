rule Win_Trojan_V3Scan_1
{
strings:
	$a0 = { 5e83ee038bd68cc88ed88c8428008ec083c62a908bfeb93706fcac34 }


condition:
	$a0
}