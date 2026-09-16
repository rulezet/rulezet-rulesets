rule Win_Trojan_Erase_3
{
strings:
	$a0 = { 0200b91000bb0f0050535152565755cd26585d5f5e5a595b5842ebe1507574207768617465 }


condition:
	$a0
}