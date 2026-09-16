rule Win_Trojan_Planters_1
{
strings:
	$a0 = { 423d9c2eff1e0301930e1fb800579c2eff1e03015152b440ba0001b968022bca9c2eff1e0301b8 }


condition:
	$a0
}