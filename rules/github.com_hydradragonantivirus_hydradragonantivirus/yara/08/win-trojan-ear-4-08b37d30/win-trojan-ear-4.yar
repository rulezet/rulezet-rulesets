rule Win_Trojan_Ear_4
{
strings:
	$a0 = { bb1000b921012e8137000083c302e2f6 }


condition:
	$a0
}