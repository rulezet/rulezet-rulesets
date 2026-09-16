rule Win_Trojan_Oggo_3
{
strings:
	$a0 = { e800005e83ee0356bf190003feb051b9cc102e280547e2fa5e09515157df1177d48f945252c5543a }


condition:
	$a0
}