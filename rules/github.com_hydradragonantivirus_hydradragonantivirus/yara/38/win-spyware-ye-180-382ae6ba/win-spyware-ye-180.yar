rule Win_Spyware_ye_180
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]b17fbb08cceb9ec8ea973aacd4f1a1 }


condition:
	$a0
}