rule Win_Trojan_Pricol_1
{
strings:
	$a0 = { 21cd218bd8b90600badf21b440cd211e8b0ef029c516ec29b440cd211fbae521b90300f606c6 }


condition:
	$a0
}