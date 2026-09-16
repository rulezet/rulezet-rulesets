rule Win_Trojan_Boot_18
{
strings:
	$a0 = { 33c08ed82e[1-3]a80175[1-3]0e07e8????cd18b9040051b400cd1372[1-3]b801021e07bb????b90100cd1359 }


condition:
	$a0
}