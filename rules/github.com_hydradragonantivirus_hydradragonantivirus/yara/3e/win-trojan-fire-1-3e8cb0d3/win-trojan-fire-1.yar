rule Win_Trojan_Fire_1
{
strings:
	$a0 = { e800005e83ee0356b9400a83c617b36d2e301c464975f9 }


condition:
	$a0
}