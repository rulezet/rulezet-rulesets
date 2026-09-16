rule Win_Trojan_R_41
{
strings:
	$a0 = { b42ccd2180fa317211b440b951008d969803cd21b43ecd21eb68b440b941008d964703cd21 }


condition:
	$a0
}