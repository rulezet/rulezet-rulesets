rule Win_Trojan_Poet_staticsig_1
{
strings:
	$a0 = { f2b14e4048b7c622ed30ed82f508f330db80f376f2f2f880970842164b23ffe2f4d2eaea486dd8eda9eaebe63a08f041 }


condition:
	$a0
}