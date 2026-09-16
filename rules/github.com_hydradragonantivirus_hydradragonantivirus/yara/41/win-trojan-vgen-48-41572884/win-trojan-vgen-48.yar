rule Win_Trojan_VGEN_48
{
strings:
	$a0 = { dc368b2f81ed030183c402061e0e1ffcb8baabcd2181fbbaab74648cd88ec0488ed88b1e030083eb6503c326a30200 }


condition:
	$a0
}