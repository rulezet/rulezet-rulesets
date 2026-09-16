rule Win_Spyware_ye_228
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]e12feb38fc9bcef89ac7eadc842151 }


condition:
	$a0
}