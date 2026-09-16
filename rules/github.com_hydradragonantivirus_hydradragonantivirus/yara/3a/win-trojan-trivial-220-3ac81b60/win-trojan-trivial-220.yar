rule Win_Trojan_Trivial_220
{
strings:
	$a0 = { faba4559cd16ba9901b44ecd21723eb29eb600b17a86e1b004d1e8cd2193b000b4aed0cccd21515232d2ba0002feceb9ff0fb440cd21b001b4aed0cc5a59 }


condition:
	$a0
}