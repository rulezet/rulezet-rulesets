rule Win_Trojan_Ursnif_1
{
strings:
	$a0 = { 5c564239385c5642362e4f4c42 }

	$a1 = { 2655736572204e616d653a }

	$a2 = { 2650617373776f72643a }

	$a3 = { 433a5c6161357662312e706462 }


condition:
	$a0 and $a1 and $a2 and $a3
}