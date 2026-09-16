rule Win_Trojan_Armageddon_4
{
strings:
	$a0 = { 018ccbea000000008bc88edbbe0001bf }


condition:
	$a0
}