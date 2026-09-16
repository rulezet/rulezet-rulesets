rule Win_Trojan_Omicron_1
{
strings:
	$a0 = { 97e50643eb06e108e108e108e2f1e9 }


condition:
	$a0
}