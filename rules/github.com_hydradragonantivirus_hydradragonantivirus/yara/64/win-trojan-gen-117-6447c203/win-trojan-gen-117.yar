rule Win_Trojan_Gen_117
{
strings:
	$a0 = { 26890e3c01c706840026018c0686 }


condition:
	$a0
}