rule Win_Trojan_Shake_4
{
strings:
	$a0 = { e800005eb80342cd213d34127503eb4890b44abbffffcd2181eb0005b44a }


condition:
	$a0
}