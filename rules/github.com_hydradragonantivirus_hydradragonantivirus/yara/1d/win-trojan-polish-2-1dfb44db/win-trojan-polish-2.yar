rule Win_Trojan_Polish_2
{
strings:
	$a0 = { d201bf0001b90300f3a45eb44ebac901 }


condition:
	$a0
}