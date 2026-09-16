rule Win_Trojan_PS_14
{
strings:
	$a0 = { e800005d83ed03b4098d96????cd218db6????bf0001b90500f3a4b81983cd213d2301750d }


condition:
	$a0
}