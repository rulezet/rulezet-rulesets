rule Win_Spyware_ye_251
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]f8c602d713b2e597396609f3933060 }


condition:
	$a0
}