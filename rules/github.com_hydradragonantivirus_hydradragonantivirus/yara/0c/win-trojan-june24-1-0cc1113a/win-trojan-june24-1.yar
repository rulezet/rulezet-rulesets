rule Win_Trojan_June24_1
{
strings:
	$a0 = { 539de80000b42acd215e81ee070181fa18067468b8aa20cd218edbc48784000e1f8984b8018c84ba010e07b93400 }


condition:
	$a0
}