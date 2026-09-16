rule Win_Trojan_Kaczor_7
{
strings:
	$a0 = { 2600252e83061300012e813e1300491175eb90 }


condition:
	$a0
}