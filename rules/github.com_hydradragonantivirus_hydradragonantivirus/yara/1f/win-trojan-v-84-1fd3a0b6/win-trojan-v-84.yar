rule Win_Trojan_V_84
{
strings:
	$a0 = { b800008ed8a07b043c057463be8400bf88000e07a5a5be2400a5a5ff0e1304a11304b106d3e08ec031ffb9b1020e }


condition:
	$a0
}