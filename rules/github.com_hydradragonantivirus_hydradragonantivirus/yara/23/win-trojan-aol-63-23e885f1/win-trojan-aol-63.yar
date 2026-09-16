rule Win_Trojan_AOL_63
{
strings:
	$a0 = { bd5c018b6e008ba602008b9e0400b44acd21a12c0089861a008b9e0000ffe386058a14460ad27406b402cd21ebf3c3 }


condition:
	$a0
}