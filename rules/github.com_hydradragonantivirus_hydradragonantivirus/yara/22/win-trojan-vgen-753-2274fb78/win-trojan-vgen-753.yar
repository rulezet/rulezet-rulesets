rule Win_Trojan_VGEN_753
{
strings:
	$a0 = { 20018b6e008ba602008b9e0400b44acd21a12c0089861a008b9e0000ffe36b058501200253e800005b5756b4ffac }


condition:
	$a0
}