rule Win_Trojan_Stoned_9
{
strings:
	$a0 = { ab0050d1e8fecc7403e96c015351520656571e558bec }


condition:
	$a0
}