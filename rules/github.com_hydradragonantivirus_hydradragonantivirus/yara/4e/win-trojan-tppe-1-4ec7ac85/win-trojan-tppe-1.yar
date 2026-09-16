rule Win_Trojan_TPPE_1
{
strings:
	$a0 = { 4d46076270632e6578655589e5b832029acd02b70181ec32028dbecffd1657bf5f180e579a7c00 }


condition:
	$a0
}