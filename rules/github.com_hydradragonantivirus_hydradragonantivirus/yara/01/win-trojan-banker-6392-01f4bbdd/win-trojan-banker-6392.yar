rule Win_Trojan_Banker_6392
{
strings:
	$a0 = { 687474703a2f2f[9]2e696e2f7765626c6f67732f726563762e706870 }


condition:
	$a0
}