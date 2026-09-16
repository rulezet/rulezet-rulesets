rule Win_Trojan_VGEN_336
{
strings:
	$a0 = { 018b6e008ba602008b9e0400b44acd21a12c00898618008b9e0000ffe3b7018a14460ad27406b402cd21ebf3c3c7 }


condition:
	$a0
}