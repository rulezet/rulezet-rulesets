rule Win_Trojan_VGEN_334
{
strings:
	$a0 = { 1f018b6e008ba602008b9e0400b44acd21a12c00898618008b9e0000ffe38b018a14460ad27406b402cd21ebf3c3c7 }


condition:
	$a0
}