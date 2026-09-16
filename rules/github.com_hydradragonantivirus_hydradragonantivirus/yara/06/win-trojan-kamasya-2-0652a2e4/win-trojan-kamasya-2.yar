rule Win_Trojan_Kamasya_2
{
strings:
	$a0 = { f300e83401585b595a5d5e5f1f072e }


condition:
	$a0
}