rule Win_Trojan_Philis_145
{
strings:
	$a0 = { 606160d9d0e800000000570f }


condition:
	$a0
}