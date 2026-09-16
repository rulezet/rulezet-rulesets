rule Win_Trojan_November17_5
{
strings:
	$a0 = { 7407e9d80159e9cb0150535152575655061e1e8bfa }


condition:
	$a0
}