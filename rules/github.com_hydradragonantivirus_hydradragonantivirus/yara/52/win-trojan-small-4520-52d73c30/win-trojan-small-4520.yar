rule Win_Trojan_Small_4520
{
strings:
	$a0 = { 8b09ffd101d5e84000000089e850e82800000055e83b00000045454545 }


condition:
	$a0
}