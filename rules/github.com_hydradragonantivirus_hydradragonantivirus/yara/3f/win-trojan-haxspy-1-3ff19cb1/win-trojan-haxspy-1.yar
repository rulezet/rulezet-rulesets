rule Win_Trojan_Haxspy_1
{
strings:
	$a0 = { e8e20c0000668cd8a804751e6a006a006a036a006a0068000000c06860410010e8d40c0000a38b5a0010 }


condition:
	$a0
}