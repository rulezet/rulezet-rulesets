rule Win_Trojan_VGEN_485
{
strings:
	$a0 = { c0cd218be55dc32e2e002a2e434f4d0055b42fcd21538bec81ec800052b41a8d5680cd21b44eb9 }


condition:
	$a0
}