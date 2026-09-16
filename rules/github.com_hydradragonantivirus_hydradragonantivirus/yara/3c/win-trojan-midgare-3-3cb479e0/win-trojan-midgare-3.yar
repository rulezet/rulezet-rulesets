rule Win_Trojan_Midgare_3
{
strings:
	$a0 = { 68ac114000e8eeffffff000000000000300000003800000000000000cc }


condition:
	$a0
}