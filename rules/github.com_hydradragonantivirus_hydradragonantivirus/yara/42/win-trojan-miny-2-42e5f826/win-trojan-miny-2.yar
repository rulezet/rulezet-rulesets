rule Win_Trojan_Miny_2
{
strings:
	$a0 = { 5e83ee03b83a4bcd210bc074408cc34b8edbb80e00 }


condition:
	$a0
}