rule Win_Trojan_Virut_395
{
strings:
	$a0 = { e813000000[19]558b6c2404[48]80fe5a }


condition:
	$a0
}