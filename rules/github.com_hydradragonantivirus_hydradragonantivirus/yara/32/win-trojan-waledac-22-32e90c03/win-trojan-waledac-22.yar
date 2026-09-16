rule Win_Trojan_Waledac_22
{
strings:
	$a0 = { 558bec83ec6c56ff15901040008bf08a06 }


condition:
	$a0
}