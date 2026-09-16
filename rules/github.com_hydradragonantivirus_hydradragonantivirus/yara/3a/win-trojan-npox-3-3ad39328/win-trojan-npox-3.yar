rule Win_Trojan_NPox_3
{
strings:
	$a0 = { 40ba1908b90300e84d048b0e13088b161508b80157e83f04b43ee83a0481fdbadc74061f }


condition:
	$a0
}