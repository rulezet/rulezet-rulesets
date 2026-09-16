rule Win_Trojan_Liberty1186_1
{
strings:
	$a0 = { 86a02e01cd2183fbff7431b40333dbcd10890e1601b401 }


condition:
	$a0
}