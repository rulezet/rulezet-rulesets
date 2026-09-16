rule Win_Trojan_Waledac_21
{
strings:
	$a0 = { 558bec83ec748b3da5ad49008d0d6fb7410003f9 }


condition:
	$a0
}