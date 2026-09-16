rule Win_Trojan_Tsunami_1
{
strings:
	$a0 = { 817bf885693a00a061ab5f00a119e499695c6698e690af61ab757b2b5f01a175762b5f009ff5752b }


condition:
	$a0
}