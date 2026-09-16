rule Win_Trojan_Solar_1
{
strings:
	$a0 = { c1e0042bc8874c112e890e2200619c2eff1e6400601eb4400e1f99b96400cd211f61ca0200 }


condition:
	$a0
}