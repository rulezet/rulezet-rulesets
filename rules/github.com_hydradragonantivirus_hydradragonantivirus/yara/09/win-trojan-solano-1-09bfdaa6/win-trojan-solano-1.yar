rule Win_Trojan_Solano_1
{
strings:
	$a0 = { 5858bf00012e893e2101582ea32301 }


condition:
	$a0
}