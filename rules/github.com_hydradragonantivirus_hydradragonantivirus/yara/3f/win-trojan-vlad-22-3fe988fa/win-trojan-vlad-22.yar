rule Win_Trojan_VLAD_22
{
strings:
	$a0 = { e800008bf4368b2c81ed1900060e0e1f078db655008dbe550033d2b81218cd212e3286420086e0e8 }


condition:
	$a0
}