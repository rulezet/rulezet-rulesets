rule Win_Spyware_ye_57
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]3684409551701b4d77244fb9d9feb6 }


condition:
	$a0
}