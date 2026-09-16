rule Win_Trojan_Markus_4
{
strings:
	$a0 = { e3d6d46b1dc51d89ee769e6e12f102d2ccd7a844dc25b485 }


condition:
	$a0
}