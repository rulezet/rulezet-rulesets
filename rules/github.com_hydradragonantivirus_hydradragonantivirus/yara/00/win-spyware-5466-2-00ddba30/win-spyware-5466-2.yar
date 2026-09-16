rule Win_Spyware_5466_2
{
strings:
	$a0 = { 53893424575733342483c4088b3424 }


condition:
	$a0
}