rule Win_Spyware_ye_189
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ba00c411d5fcafd9fba0c3355d7a2a }


condition:
	$a0
}