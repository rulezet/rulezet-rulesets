rule Win_Spyware_ye_56
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]35fb3f94507722547e234eb8d8fdb5 }


condition:
	$a0
}