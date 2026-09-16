rule Win_Trojan_Perfume_5
{
strings:
	$a0 = { bf0000f3a481ec0004bfba000657cb0e1f8e065f008b36 }


condition:
	$a0
}