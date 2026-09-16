rule Win_Trojan_Fakealert_74
{
strings:
	$a0 = { 68692c20626f746e6574204a61636b2068657265 }


condition:
	$a0
}