rule Win_Trojan_DeicideTroj_1
{
strings:
	$a0 = { ba7e01be820157b42fcd218bfbb44eb92700cd217240b8014333c98d551ecd21b8013d8d551ecd2193b4408b0c8d5402cd21b801578b4d168b5518cd21b43ecd }


condition:
	$a0
}