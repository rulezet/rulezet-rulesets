rule Win_Trojan_Trojan_267
{
strings:
	$a0 = { 0132260001be0301b90300e8c6ff }


condition:
	$a0
}