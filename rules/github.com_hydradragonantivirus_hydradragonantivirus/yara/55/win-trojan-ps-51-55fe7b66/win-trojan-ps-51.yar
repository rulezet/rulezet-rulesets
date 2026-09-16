rule Win_Trojan_PS_51
{
strings:
	$a0 = { 447458b44abbffffcd2183eb3890b44acd217247832e020038 }


condition:
	$a0
}