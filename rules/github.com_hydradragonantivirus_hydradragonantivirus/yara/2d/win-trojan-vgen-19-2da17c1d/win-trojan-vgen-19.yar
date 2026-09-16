rule Win_Trojan_Vgen_19
{
strings:
	$a0 = { 8b6e008ba602008b9e0400b44acd21a12c00898618008b9e0000ffe3f0018a14460ad27406b402cd21ebf3c346 }


condition:
	$a0
}