rule Win_Trojan_Packed_104
{
strings:
	$a0 = { 87df25c000000033c705bd00000033ff83c002bbb6414100fe034381fbc44341 }


condition:
	$a0
}