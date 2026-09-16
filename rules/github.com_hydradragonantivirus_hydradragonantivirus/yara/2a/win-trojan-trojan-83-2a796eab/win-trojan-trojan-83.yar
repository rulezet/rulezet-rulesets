rule Win_Trojan_Trojan_83
{
strings:
	$a0 = { 3401b419cd2104412ea265032ea2b103bf6703578bf2807c013a750d8a042ea265032ea2b103 }


condition:
	$a0
}