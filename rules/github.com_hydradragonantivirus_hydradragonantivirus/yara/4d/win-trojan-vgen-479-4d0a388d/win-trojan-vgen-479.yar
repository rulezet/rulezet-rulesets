rule Win_Trojan_VGEN_479
{
strings:
	$a0 = { 18c8008c4c1a1eb82012cd2f53b81612268a1dcd2f5b26c645020226f64505807551268b452826 }


condition:
	$a0
}