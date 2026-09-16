rule Win_Trojan_Baron_2
{
strings:
	$a0 = { 53b6170355fe362221b49eb99e025396780313215586a703f303de895815dd3317330cb8de421321 }


condition:
	$a0
}