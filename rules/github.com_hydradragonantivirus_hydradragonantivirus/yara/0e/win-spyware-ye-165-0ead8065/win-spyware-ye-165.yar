rule Win_Spyware_ye_165
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]a268ac79bde497c1e3882b9dc5e292 }


condition:
	$a0
}