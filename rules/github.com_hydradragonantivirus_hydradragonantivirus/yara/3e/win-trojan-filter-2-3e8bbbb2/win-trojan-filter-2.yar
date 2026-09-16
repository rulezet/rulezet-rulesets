rule Win_Trojan_Filter_2
{
strings:
	$a0 = { c882a8aaa8ada3f404a3f804a3fc04a25804fcb44abb8000cd21488ed8c70601000800b40dcd212bc08ed8c41e0400 }


condition:
	$a0
}