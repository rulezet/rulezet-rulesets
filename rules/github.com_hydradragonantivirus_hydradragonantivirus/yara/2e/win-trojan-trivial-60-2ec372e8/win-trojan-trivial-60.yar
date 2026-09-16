rule Win_Trojan_Trivial_60
{
strings:
	$a0 = { b111e8fdfe0ac07536ba0001b11ae8f1febe8000bf6c018bd7b92500f3a4b116e8dffeb115e8dafeb110e8d5fe }


condition:
	$a0
}