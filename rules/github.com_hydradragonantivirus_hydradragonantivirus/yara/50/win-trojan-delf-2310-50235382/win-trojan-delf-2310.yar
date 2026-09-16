rule Win_Trojan_Delf_2310
{
strings:
	$a0 = { 8b45ece89088faff8b45e8e88888faff8b45e4e88088faff8b45e0e87888faff6a00668b0d40aa4500b202b84caa4500e8f7defcff33c05a59596489106829aa4500 }


condition:
	$a0
}