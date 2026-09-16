rule Win_Trojan_Axe_3
{
strings:
	$a0 = { 8c1621012e89261f018ccc8ed4bc5b00fb601e062e8a260a000e07bb5d00b9600026302743d0cce2f8b806fecd }


condition:
	$a0
}