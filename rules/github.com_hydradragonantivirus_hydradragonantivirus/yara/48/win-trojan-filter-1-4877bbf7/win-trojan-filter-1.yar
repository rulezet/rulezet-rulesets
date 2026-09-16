rule Win_Trojan_Filter_1
{
strings:
	$a0 = { c882a8aaa8ada3f804a3fc04a30005a25c04fcb44abb8000cd21488ed8c70601000800b40dcd212bc08ed8c41e0400 }


condition:
	$a0
}