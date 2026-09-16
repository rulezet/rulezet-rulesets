rule Win_Spyware_ye_110
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]6bb17542862d5802acd1fcee963363 }


condition:
	$a0
}