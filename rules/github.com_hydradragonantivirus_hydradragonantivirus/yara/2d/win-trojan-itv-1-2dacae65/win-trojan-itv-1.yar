rule Win_Trojan_Itv_1
{
strings:
	$a0 = { e800005d81ed30018db6e902bf0001b90300fcf3a406b42fcd21899ef3028c86f502b41a8d96f702cd218e062c0033 }


condition:
	$a0
}