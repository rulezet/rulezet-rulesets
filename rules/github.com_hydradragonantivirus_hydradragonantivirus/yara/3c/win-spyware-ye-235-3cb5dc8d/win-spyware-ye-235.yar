rule Win_Spyware_ye_235
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]e836f2c703a2d5872956796303a0d0 }


condition:
	$a0
}