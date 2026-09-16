rule Win_Spyware_ye_209
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ce1cd82de98833650fbce7d1f196ce }


condition:
	$a0
}