rule Win_Trojan_Grog_12
{
strings:
	$a0 = { 3d47524f47ba9e0047524f47cd2147524f479347524f }


condition:
	$a0
}