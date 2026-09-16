rule Win_Trojan_DREG_1
{
strings:
	$a0 = { 0400cc8d862703ffd09c8920ca76cee9dea87977fcad6175fcda3ea43c2401ed05d3236c7fe131a412eabfd323df72 }


condition:
	$a0
}