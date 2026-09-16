rule Win_Spyware_ye_252
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]f9c703d014b3e690325f02f49c3969 }


condition:
	$a0
}