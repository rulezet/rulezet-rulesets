rule Win_Trojan_Oxana_II_2
{
strings:
	$a0 = { 6d8e0534a78377fa1605f7df2a378d09338e2d378377fa168f3660bc210133bc390f33b7c62bfa16 }


condition:
	$a0
}