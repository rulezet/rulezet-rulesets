rule Win_Trojan_Solar_4
{
strings:
	$a0 = { e0042bc8874c0a2e890e2300619c2eff1e7a00601eb4400e1f99b97a00cd211f61ca0200 }


condition:
	$a0
}