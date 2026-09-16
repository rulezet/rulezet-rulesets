rule Win_Trojan_Shutdown_1
{
strings:
	$a0 = { 2acd2180fe037541ba0901b409cd2133c0cd13b80903b90101ba8000cd13fec680fe0575f7fec2 }


condition:
	$a0
}