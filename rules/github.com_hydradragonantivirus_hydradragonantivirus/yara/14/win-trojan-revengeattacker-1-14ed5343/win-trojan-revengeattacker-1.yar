rule Win_Trojan_RevengeAttacker_1
{
strings:
	$a0 = { 40803f00750a40803f007504f8e9 }


condition:
	$a0
}