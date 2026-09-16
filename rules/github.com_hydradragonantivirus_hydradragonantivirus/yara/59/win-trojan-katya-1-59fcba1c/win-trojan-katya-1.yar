rule Win_Trojan_Katya_1
{
strings:
	$a0 = { e800005e505683c615ba2733b9cd003114ade2fbbf00015e }


condition:
	$a0
}