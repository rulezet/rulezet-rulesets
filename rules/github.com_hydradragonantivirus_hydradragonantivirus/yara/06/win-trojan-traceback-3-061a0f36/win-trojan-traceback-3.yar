rule Win_Trojan_Traceback_3
{
strings:
	$a0 = { 5101818451015f088c8c53018884e300e8e3 }


condition:
	$a0
}