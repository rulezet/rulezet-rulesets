rule Win_Spyware_ye_212
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]d11fdb28ec8b3e680ab7daccf491c1 }


condition:
	$a0
}