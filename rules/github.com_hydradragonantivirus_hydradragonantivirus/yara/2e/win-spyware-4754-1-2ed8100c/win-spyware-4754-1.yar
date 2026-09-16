rule Win_Spyware_4754_1
{
strings:
	$a0 = { 434b6072037301ebe8000000 }


condition:
	$a0
}