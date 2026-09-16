rule Win_Trojan_Halter_1
{
strings:
	$a0 = { e817000683f97da6ddcb67da2d419b8c6778aa153c6224783a34be0301b90b00813434674646e2f8c3 }


condition:
	$a0
}