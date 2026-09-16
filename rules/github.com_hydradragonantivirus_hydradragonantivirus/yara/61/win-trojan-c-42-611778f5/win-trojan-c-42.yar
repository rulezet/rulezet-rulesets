rule Win_Trojan_C_42
{
strings:
	$a0 = { 02e8ba00b45cb92300ba4c02e8af007231bec402e85800b83451bac402e89e007204b45d }


condition:
	$a0
}