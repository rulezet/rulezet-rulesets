rule Win_Trojan_Grog_8
{
strings:
	$a0 = { 0101ad50b9120fac8ad05e81c61e01ac02c28844fffec2 }


condition:
	$a0
}