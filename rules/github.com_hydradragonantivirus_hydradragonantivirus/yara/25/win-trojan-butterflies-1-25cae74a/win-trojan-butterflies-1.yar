rule Win_Trojan_Butterflies_1
{
strings:
	$a0 = { b650028d962c0252eb3cb41aba8000cd2133c033db }


condition:
	$a0
}