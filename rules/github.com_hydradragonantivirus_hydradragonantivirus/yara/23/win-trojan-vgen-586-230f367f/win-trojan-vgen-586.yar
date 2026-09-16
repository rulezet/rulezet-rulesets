rule Win_Trojan_VGEN_586
{
strings:
	$a0 = { 5d81ed03001e06cd2a3d0000753bb430cd213c047233b89519cd2181fa7519742833c08ec00e1f8db60000bfe001b9 }


condition:
	$a0
}