rule Win_Trojan_Moron_1
{
strings:
	$a0 = { bb08595933ffeb0bb895015056e8710859594783ff287cf05633c050b8320050b8020050e81f12 }


condition:
	$a0
}