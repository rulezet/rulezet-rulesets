rule Win_Trojan_Peed_64
{
strings:
	$a0 = { 68bdcaffff }

	$a1 = { 0fb754960201c2c1ca18 }


condition:
	$a0 and $a1
}