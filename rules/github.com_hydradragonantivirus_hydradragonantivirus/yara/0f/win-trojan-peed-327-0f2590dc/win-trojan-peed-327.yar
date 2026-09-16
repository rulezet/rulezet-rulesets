rule Win_Trojan_Peed_327
{
strings:
	$a0 = { 89eff8ba67745400fc73425589e551418b7d1066abc1c809c1c807aa86c4aa83c70283ef }


condition:
	$a0
}