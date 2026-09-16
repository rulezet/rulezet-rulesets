rule Win_Trojan_Peed_243
{
strings:
	$a0 = { 89eff8ba67745400fc7340ff1557744500e88d18f7568f0544774500f7d36884 }


condition:
	$a0
}