rule Win_Trojan_Khizhnjak_19
{
strings:
	$a0 = { a34202b900008b1e3c02b80042cd2172428d161001b932018b1e3c02b440cd217231b90000 }


condition:
	$a0
}