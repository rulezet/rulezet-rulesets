rule Win_Trojan_Gen_65
{
strings:
	$a0 = { e70051bb37018a2f322e0201882f4381fb5f047ef159c3ba00018b1ee40153e8e0ff5bb92803b440cd2153 }


condition:
	$a0
}