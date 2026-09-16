rule Win_Trojan_W13_2
{
strings:
	$a0 = { 4fcd2173153c127403e90d0183fdff75 }


condition:
	$a0
}