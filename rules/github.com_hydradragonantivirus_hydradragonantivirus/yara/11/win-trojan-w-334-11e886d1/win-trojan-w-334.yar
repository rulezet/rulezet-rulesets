rule Win_Trojan_W_334
{
strings:
	$a0 = { 171e07b41a8bd6ff17b44e8d978b00000033c9ff17725c8d561e6066b8023dff177247938d562bb504b43fff170fb64a }


condition:
	$a0
}