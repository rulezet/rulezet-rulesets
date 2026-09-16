rule Win_Trojan_SbBot_1
{
strings:
	$a0 = { 7ad84abbadd73866ed895c7b40f5793beed9104671d1ef01d4c5896e839da962fae121d12a3cb3e441e6e4b513e83d76a04b167d8bcf97a883627bccbe342006ccc06e18b15bfd88b20f116401fcea74 }


condition:
	$a0
}