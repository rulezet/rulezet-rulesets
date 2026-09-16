rule Win_Trojan_Waledac_32
{
strings:
	$a0 = { 8bc8c1d20933c233c2bac4000000c1e806c1c8 }


condition:
	$a0
}