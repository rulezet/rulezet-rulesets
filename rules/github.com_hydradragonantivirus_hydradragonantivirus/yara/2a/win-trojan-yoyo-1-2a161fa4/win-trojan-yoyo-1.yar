rule Win_Trojan_Yoyo_1
{
strings:
	$a0 = { bb7100be607cbf6f7cb91e00ac3422ee87f787d3e2f633c9ba4f18b70732c0b406cd10b401 }


condition:
	$a0
}