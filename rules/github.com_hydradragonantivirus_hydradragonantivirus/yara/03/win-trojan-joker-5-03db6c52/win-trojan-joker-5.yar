rule Win_Trojan_Joker_5
{
strings:
	$a0 = { 0301882f4381fb6e047ef159c3ba00018b1ee50153e8e0ff5bb93603b440cd2153 }


condition:
	$a0
}