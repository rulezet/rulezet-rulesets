rule Win_Trojan_Piter_1
{
strings:
	$a0 = { 15ca8b361b01bf00018b0e1d018b1e }


condition:
	$a0
}