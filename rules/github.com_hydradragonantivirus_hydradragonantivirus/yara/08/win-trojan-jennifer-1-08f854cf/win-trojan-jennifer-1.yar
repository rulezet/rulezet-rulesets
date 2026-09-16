rule Win_Trojan_Jennifer_1
{
strings:
	$a0 = { bd0000bf23013e8b86????b995052e30034726a3????8cc026a1????e2f0 }


condition:
	$a0
}