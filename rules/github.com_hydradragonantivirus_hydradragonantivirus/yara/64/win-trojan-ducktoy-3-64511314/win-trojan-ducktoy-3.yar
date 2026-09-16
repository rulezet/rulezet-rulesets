rule Win_Trojan_Ducktoy_3
{
strings:
	$a0 = { 2b2d2b00ffffffff0d0000004475636b746f792b7061676572000000ffffffff3b00000066726f6d3d4475636b746f79 }


condition:
	$a0
}