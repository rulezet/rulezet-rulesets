rule Win_Spyware_5851_1
{
strings:
	$a0 = { 81c33034884f5481eb3034 }


condition:
	$a0
}