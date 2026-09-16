rule Win_Trojan_Ear_2
{
strings:
	$a0 = { 1301b901022e8137000083c302e2f6 }


condition:
	$a0
}