rule Win_Trojan_DarkElf_5
{
strings:
	$a0 = { 18b927a2ac8d83b3251fa12094d99ed83c629aaa11c51fa2918b82f71e3707a47101b8f5071f7d00 }


condition:
	$a0
}