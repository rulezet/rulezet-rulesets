rule Win_Trojan_SVC_18
{
strings:
	$a0 = { 84181281eee00f2e8c84db112e899cdd112effb414122e }


condition:
	$a0
}