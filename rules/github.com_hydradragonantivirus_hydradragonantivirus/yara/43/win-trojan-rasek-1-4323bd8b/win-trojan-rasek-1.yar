rule Win_Trojan_Rasek_1
{
strings:
	$a0 = { ba8001b90100b8ff03cd13b403fec6cd1373f8b6fffec575f2f4 }


condition:
	$a0
}