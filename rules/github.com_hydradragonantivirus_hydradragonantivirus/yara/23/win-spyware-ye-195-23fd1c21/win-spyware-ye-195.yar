rule Win_Spyware_ye_195
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]c00eca1fdbfaaddf812e51bbdbf8a8 }


condition:
	$a0
}