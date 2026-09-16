rule Win_Trojan_Sentinel_6
{
strings:
	$a0 = { 17fdb8eb0d8bd08b46f62bc28946f6 }


condition:
	$a0
}