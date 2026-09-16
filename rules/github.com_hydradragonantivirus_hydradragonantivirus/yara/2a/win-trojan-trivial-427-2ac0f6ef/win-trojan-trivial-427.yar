rule Win_Trojan_Trivial_427
{
strings:
	$a0 = { b92700ba5e01cd21720ee816007504b44febf3b8014ccd21fab40299b90001cd26ebfeb8023dba9e00cd2193 }


condition:
	$a0
}