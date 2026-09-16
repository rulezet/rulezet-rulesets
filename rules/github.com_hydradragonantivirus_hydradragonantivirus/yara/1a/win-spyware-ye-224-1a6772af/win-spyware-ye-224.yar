rule Win_Spyware_ye_224
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]dd23e73cf89fcafca6cbf6e080255d }


condition:
	$a0
}