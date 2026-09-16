rule Win_Trojan_RMC_1
{
strings:
	$a0 = { 2e3b05b404cd1a81fa1602750cb0ade664e82500e80300 }


condition:
	$a0
}