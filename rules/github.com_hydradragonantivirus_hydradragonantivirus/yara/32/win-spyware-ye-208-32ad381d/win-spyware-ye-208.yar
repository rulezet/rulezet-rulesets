rule Win_Spyware_ye_208
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]cd13d72ce88f3a6c16bbe6d0f095cd }


condition:
	$a0
}