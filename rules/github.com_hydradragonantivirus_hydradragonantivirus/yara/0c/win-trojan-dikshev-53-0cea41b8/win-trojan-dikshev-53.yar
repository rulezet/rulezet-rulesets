rule Win_Trojan_Dikshev_53
{
strings:
	$a0 = { b44eb19e87cecd217301c38bd6ac3c2e75fbc704636fc644026db45bcd2172ea93b440ba33009087d1ebdb2a2e652a00 }


condition:
	$a0
}