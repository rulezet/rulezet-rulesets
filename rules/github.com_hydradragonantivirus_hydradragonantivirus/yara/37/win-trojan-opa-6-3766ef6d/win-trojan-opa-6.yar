rule Win_Trojan_Opa_6
{
strings:
	$a0 = { 03018bd8b4401e0e1fba0001b9c8009c2eff1e03011fcf }


condition:
	$a0
}