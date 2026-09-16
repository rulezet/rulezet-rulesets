rule Win_Trojan_Skism_3
{
strings:
	$a0 = { eb029000e80300e9e70051bb38018a2f322e0301882f4381fb60047ef159c3 }


condition:
	$a0
}