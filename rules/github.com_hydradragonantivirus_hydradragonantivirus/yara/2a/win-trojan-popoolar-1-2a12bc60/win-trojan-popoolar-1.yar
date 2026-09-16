rule Win_Trojan_PopooLar_1
{
strings:
	$a0 = { e900000e1fba7901b409cd21ba7501e80500b8004ccd2155b42fcd215389e581ec800052b41a8d5680cd21b44eb927005acd217207e80d00b44febf589ecb41a5acd21 }


condition:
	$a0
}