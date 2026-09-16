rule Win_Trojan_Trivial_484
{
strings:
	$a0 = { 33c9ba7901cd217261b8003dba9e00cd2193b80057cd215251b43fb90400ba7d01cd21b43ecd21803e8001667504 }


condition:
	$a0
}