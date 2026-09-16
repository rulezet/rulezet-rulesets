rule Win_Trojan_Zarina_1
{
strings:
	$a0 = { 01a3cf01a1d101a3d301b419cd21fec0a22801ba0301b41acd21b411c3ba2801cd21c3b41aba4d01cd21b40fba03 }


condition:
	$a0
}