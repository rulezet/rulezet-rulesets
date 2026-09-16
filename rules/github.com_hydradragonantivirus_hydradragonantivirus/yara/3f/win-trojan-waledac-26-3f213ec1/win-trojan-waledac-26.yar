rule Win_Trojan_Waledac_26
{
strings:
	$a0 = { 558bec83ec4483c66956ff15441040008bf08a06 }


condition:
	$a0
}