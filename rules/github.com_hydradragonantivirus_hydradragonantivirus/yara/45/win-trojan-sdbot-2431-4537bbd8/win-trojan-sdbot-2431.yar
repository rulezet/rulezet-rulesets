rule Win_Trojan_SdBot_2431
{
strings:
	$a0 = { 5787ea87ea83c404e800000000eb0164 }


condition:
	$a0
}