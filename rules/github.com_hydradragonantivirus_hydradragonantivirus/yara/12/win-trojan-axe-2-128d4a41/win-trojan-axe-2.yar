rule Win_Trojan_Axe_2
{
strings:
	$a0 = { fa2e8c1601012e8926ff008ccc8ed4bc5b00fb601e062e8a260a000e07bb5d00b9400026302743d0cce2f8b805fecd }


condition:
	$a0
}