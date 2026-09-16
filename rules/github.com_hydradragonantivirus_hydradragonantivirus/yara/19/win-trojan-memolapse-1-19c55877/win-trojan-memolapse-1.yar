rule Win_Trojan_MemoLapse_1
{
strings:
	$a0 = { 90b801faba4559cd16e800005d81ed0f018d9e2202ff374343ff37b41a8d962602cd21ccb44e8d961a02cd217203eb0490e9c300b42fcd2133c08d771e }


condition:
	$a0
}