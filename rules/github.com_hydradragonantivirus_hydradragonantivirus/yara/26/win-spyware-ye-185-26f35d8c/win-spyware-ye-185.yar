rule Win_Spyware_ye_185
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]b604c015d1f09bcdf7a4cf39597e36 }


condition:
	$a0
}