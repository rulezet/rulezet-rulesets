rule Win_Trojan_MutaGen_1
{
strings:
	$a0 = { 04be8401bbeaaf71002e011c81f39bed463d855646904d75f0fe508f1a973d9abedcd695bf1604be8a37a31c5477 }


condition:
	$a0
}