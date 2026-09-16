rule Win_Spyware_ye_159
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]9c62a673b7de89335d02ad1f476c24 }


condition:
	$a0
}