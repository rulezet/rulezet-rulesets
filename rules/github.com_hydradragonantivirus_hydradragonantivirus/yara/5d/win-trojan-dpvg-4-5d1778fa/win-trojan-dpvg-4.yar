rule Win_Trojan_DPVG_4
{
strings:
	$a0 = { 6b652f534d469a00008c005589e581ec0001bfbf040e57bf52001e57b8ff00509a16098c00bf }


condition:
	$a0
}