rule Win_Trojan_Small_77_1
{
strings:
	$a0 = { 637269212bfcdb850d6f781e7262756d6c7476c54adff0427b6a6a6f56b9796f6a19007a7770655ef8eddb72006d626f79651b6171 }


condition:
	$a0
}