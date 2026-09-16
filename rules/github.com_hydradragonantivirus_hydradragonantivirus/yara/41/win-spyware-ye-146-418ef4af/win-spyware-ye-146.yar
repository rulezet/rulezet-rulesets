rule Win_Spyware_ye_146
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]8f5d996eaac9fcaed0fda00aaacf87 }


condition:
	$a0
}