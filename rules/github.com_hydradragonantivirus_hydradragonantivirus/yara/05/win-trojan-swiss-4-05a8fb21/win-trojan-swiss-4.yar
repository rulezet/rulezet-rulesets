rule Win_Trojan_Swiss_4
{
strings:
	$a0 = { 3fb18f8bd6cd21803c5074178bd7e8 }


condition:
	$a0
}