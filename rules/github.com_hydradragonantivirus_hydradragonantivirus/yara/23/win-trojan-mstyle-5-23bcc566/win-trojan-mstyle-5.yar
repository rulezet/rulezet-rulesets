rule Win_Trojan_Mstyle_5
{
strings:
	$a0 = { 0ae76d0866af64b234a245b96c5effb0954b6d425d7722e43bf5dafcb882 }


condition:
	$a0
}