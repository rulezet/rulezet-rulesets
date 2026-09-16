rule Win_Trojan_I13_32
{
strings:
	$a0 = { 9124d4362dcd4c090962bb47c0450dc15b0dd4282dce4c1c0707bb47c00b07c1990bd428bf085e61 }


condition:
	$a0
}