rule Win_Trojan_Invol_4
{
strings:
	$a0 = { 3d004b7403e97b025053521e06b8023dcd217303e967 }


condition:
	$a0
}