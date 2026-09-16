rule Win_Trojan_Dzino_1
{
strings:
	$a0 = { b00233c933d2cd218bd583ea05b9e803b440cd217212b8015783c6168b0c83c91f83c6028b14 }


condition:
	$a0
}