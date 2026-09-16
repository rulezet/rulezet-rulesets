rule Win_Trojan_Lawine_2
{
strings:
	$a0 = { cd468bcbfc0675cfcf44d1abcb77cf8d02eebdfe7b8f76efcf75cfcf53e130d185cbbdee77cd8dfc }


condition:
	$a0
}