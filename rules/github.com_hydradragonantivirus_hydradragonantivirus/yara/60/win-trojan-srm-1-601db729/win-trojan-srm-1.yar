rule Win_Trojan_SRM_1
{
strings:
	$a0 = { 1059807efe0a7409807efe147403e9020133c050e850 }


condition:
	$a0
}