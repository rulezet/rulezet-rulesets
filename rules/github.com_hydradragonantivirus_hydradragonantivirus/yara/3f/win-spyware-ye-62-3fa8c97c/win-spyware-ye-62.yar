rule Win_Spyware_ye_62
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]3b814592567d28527c214cbee68333 }


condition:
	$a0
}