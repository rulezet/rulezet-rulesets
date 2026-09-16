rule Win_Spyware_4734_1
{
strings:
	$a0 = { 6056525e81ee72758e3b }


condition:
	$a0
}