rule Win_Trojan_Philis_105
{
strings:
	$a0 = { 4048604048e8000000005733fe5f03f72bf75381f3c23700005b5ab81d010000534b5b5633f7 }


condition:
	$a0
}