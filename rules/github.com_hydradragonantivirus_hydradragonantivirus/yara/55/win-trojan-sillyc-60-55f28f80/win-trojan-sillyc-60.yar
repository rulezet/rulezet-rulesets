rule Win_Trojan_SillyC_60
{
strings:
	$a0 = { 81ee1601b41a8d94b601cd21568db4b201bf0001b90300f3a45eb44e8d94a901b90700cd21725beb0ab43ecd21b44f }


condition:
	$a0
}