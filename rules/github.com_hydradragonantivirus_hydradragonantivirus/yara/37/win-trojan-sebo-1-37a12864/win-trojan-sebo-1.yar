rule Win_Trojan_Sebo_1
{
strings:
	$a0 = { f7cd133c017419b81335cd212e8c0602082e891e0008b813250e1fba14029090071f61c33d00 }


condition:
	$a0
}