rule Win_Trojan_VGEN_660
{
strings:
	$a0 = { 9090e800005a83ea03525d8bf281c6f901bf0001b90500acaae2fcb42acd2180fe0c750880fa197503e9ce0180fe }


condition:
	$a0
}