rule Win_Spyware_ye_112
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]6db3774c882f5a0cb6db867010b5ed }


condition:
	$a0
}