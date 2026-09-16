rule Win_Trojan_Jerusalem_17
{
strings:
	$a0 = { 10002bc85803c183d20050528b1e4201b440cd213bc15a587402ebd45052b104d3e8b10cd3e203c2 }


condition:
	$a0
}