rule Win_Trojan_Trojan_222
{
strings:
	$a0 = { 35cec9c730c61d2ce2d3d034f608fb5cfb5da960d00df636fb5cfb5de3e4f6d4a524429e1fe13cc7 }


condition:
	$a0
}