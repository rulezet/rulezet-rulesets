rule Win_Trojan_RevengeAttacker_2
{
strings:
	$a0 = { 33d29cff1e0901b4408b1eb901b9670581e90001ba0001 }


condition:
	$a0
}