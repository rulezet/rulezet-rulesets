rule Win_Trojan_VGEN_330
{
strings:
	$a0 = { 8b6e008ba602008b9e0400b44acd21a12c00898618008b9e0000ffe34c02c7860e00ffff8bd633c9b8023c0bff }


condition:
	$a0
}