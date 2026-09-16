rule Win_Trojan_Iosys_1
{
strings:
	$a0 = { b90004cd18b43ecd18614060b80242995259cd18b440c70617050d0ab119ba0005cd1861d2e9cd18 }


condition:
	$a0
}