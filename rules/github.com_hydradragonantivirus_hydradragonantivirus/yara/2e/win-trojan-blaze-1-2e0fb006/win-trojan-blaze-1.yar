rule Win_Trojan_Blaze_1
{
strings:
	$a0 = { c9ba0001cd21ba9e00bf9e00b000b90c00f2aec60500b43db001cd2189c3b440ba0001b91c01cd21b43ecd21b44fba0001 }


condition:
	$a0
}