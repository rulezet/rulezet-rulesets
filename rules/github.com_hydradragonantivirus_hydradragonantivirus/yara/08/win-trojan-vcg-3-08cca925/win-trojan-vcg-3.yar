rule Win_Trojan_VCG_3
{
strings:
	$a0 = { ff1281e8ffd25587d55d81c2ae0281c20400b9fbd681f1ffd690cd219055bd024281edffd687e8 }


condition:
	$a0
}