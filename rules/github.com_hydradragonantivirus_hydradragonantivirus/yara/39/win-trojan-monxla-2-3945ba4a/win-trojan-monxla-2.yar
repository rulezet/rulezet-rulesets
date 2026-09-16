rule Win_Trojan_Monxla_2
{
strings:
	$a0 = { 1702908bd681eae701cd21721e3d17 }


condition:
	$a0
}