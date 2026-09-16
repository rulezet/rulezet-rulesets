rule Win_Trojan_Piter_2
{
strings:
	$a0 = { ca8b361b01bf00018b0e1d018b1e1901cd21ff361f01c3 }


condition:
	$a0
}