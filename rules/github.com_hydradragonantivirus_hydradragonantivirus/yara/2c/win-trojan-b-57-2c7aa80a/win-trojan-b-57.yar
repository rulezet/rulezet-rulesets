rule Win_Trojan_B_57
{
strings:
	$a0 = { 50900e1fbb3c7c8b0735ff7f8907434381fb5a7d72f1c3 }


condition:
	$a0
}