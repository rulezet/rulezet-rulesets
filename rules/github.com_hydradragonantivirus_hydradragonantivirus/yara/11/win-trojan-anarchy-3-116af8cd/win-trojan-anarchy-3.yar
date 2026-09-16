rule Win_Trojan_Anarchy_3
{
strings:
	$a0 = { dc7d4002355bc3bbbf35566e785e2c59354f6392354b6389 }


condition:
	$a0
}