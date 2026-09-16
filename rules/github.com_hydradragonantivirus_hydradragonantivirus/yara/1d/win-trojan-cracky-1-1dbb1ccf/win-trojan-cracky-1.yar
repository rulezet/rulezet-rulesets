rule Win_Trojan_Cracky_1
{
strings:
	$a0 = { f900027612b80300cd10b409ba280ce86cfffaf4e9c400 }


condition:
	$a0
}