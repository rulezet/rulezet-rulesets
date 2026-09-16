rule Win_Trojan_Zbot_1228
{
strings:
	$a0 = { 535e01df8b461c536683ea5b6633c001e9506843be044081c93dfd6b4f8b157030400040ff }


condition:
	$a0
}