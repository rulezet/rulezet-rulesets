rule Win_Trojan_Timber_1
{
strings:
	$a0 = { cce4403c1777f4813e0afe220272ec813e0afe7cfa77e4b8023dcd2193b43fb92202bacbfacd21 }


condition:
	$a0
}