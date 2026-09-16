rule Win_Trojan_Thorin_1
{
strings:
	$a0 = { 03e9b600be0504e8d50033c0cd163c627403e9a500e89b00596f752064656d6f6e737472617465 }


condition:
	$a0
}