rule Win_Trojan_Inv_1
{
strings:
	$a0 = { 833e8802057403e98cfdbf38471e579aa8099f0189ec5dc30b433a5c4c5450572e45584510 }


condition:
	$a0
}