rule Win_Trojan_Flagyll_2
{
strings:
	$a0 = { eb008cc8488ed8803e00005a753aa103002d0001a303008bd88cc003c38ec0b971018cd8408ed8be0001bf0001f3a48ed9be8400bf7102ba4901ad3bc27409aba506 }


condition:
	$a0
}