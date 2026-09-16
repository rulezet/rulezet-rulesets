rule Win_Trojan_N_20
{
strings:
	$a0 = { 5e81ee4e07b94a07b800002e310446fec440e2f7c3 }


condition:
	$a0
}