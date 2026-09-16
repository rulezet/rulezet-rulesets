rule Win_Trojan_U_17
{
strings:
	$a0 = { ca040889f7b94d01000066ad6635c1af66abe2f6 }


condition:
	$a0
}