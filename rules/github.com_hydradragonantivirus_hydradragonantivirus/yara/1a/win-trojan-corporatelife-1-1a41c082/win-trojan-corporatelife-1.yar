rule Win_Trojan_CorporateLife_1
{
strings:
	$a0 = { 060e1fbbffffbeffff8034ff464b75f9c3 }


condition:
	$a0
}