rule Win_Trojan_Zbot_1233
{
strings:
	$a0 = { 89dff7dee81900000000630000895a5300000000c464 }

	$a1 = { 79347d447a7b7c7d79954b7e5c }


condition:
	$a0 and $a1
}