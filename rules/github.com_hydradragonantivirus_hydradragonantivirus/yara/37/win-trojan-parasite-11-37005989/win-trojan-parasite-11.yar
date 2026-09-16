rule Win_Trojan_Parasite_11
{
strings:
	$a0 = { 02b405b680b500cd13b9140051e80a00b90040e2fe59e2 }


condition:
	$a0
}