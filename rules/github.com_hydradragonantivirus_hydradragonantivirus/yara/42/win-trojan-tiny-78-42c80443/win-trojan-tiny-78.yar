rule Win_Trojan_Tiny_78
{
strings:
	$a0 = { 05034413c1e0042bc8874c112e890e2000619c0ee81200601eb4400e1f99b96100cd211f61ca }


condition:
	$a0
}