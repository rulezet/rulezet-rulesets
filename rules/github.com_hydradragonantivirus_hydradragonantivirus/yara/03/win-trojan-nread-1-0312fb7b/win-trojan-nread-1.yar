rule Win_Trojan_NRead_1
{
strings:
	$a0 = { e800005e81ee830456b4fecd2f3c4a751feb039000015e568cc88ed88ec083ee05bf0001b90500f3 }


condition:
	$a0
}