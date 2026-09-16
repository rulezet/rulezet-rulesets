rule Win_Spyware_ye_60
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]3987439054732650721f42b4dcf9a9 }


condition:
	$a0
}