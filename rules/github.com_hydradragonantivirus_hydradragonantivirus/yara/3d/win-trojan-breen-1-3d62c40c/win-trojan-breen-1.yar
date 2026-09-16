rule Win_Trojan_Breen_1
{
strings:
	$a0 = { e80000000058908be881ed0510400083fd00744fbe6310400003f533c9eb04 }


condition:
	$a0
}