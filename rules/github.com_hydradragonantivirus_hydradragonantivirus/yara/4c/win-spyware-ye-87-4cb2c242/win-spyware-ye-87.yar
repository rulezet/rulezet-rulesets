rule Win_Spyware_ye_87
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]549a5eab6f16416b15bae5d7ffa4dc }


condition:
	$a0
}