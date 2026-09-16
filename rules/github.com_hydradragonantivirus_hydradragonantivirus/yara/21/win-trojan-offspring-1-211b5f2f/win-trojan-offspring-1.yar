rule Win_Trojan_Offspring_1
{
strings:
	$a0 = { 90bf????90b92d028135????479090479090e2f4 }


condition:
	$a0
}