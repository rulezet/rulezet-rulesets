rule Win_Trojan_Carzy_1
{
strings:
	$a0 = { 0e1fffe30e1f8cc383c310011e1124011e1524b4e8cd2180fcab7513fa8e1615248b261324 }


condition:
	$a0
}