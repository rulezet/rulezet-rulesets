rule Win_Trojan_Gen_257
{
strings:
	$a0 = { 9a00001b019a0d00b9005589e5b800029acd021b0181ec0002bf00000e57bf7a501e57b8ff00509a120a1b01bf7a511e }


condition:
	$a0
}