rule Win_Trojan_OGWO_1
{
strings:
	$a0 = { e800005e505683c615ba2c22b9cd003114ade2fbbf00015e }


condition:
	$a0
}