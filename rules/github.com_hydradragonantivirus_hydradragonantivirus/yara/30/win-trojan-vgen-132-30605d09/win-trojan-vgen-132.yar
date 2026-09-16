rule Win_Trojan_Vgen_132
{
strings:
	$a0 = { 4b04b9d100871481eab404eb0980e6213402eb0acc2d50e4213402ebf174e62158eb02eabf4281eab404eb0980e621 }


condition:
	$a0
}