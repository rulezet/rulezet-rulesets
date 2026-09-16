rule Win_Trojan_ARCV_33
{
strings:
	$a0 = { bb1401b9da012e8137000083c3024975f5 }


condition:
	$a0
}