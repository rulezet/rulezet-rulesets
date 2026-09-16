rule Win_Trojan_Egobot_1
{
strings:
	$a0 = { 3f73746172745f646f776e6c6f616465724040594148585a }


condition:
	$a0
}