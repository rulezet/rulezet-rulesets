rule Win_Trojan_Wit_6
{
strings:
	$a0 = { 03cd217203e9f4fe8b0e12038b36bf0281c60001e8d7ffba80008a660ccd21b43b8b16140383 }


condition:
	$a0
}