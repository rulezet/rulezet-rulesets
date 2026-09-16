rule Win_Trojan_Search_15
{
strings:
	$a0 = { 1f83f91e74de3e8abe390380e70180ff01750eb443b0 }


condition:
	$a0
}