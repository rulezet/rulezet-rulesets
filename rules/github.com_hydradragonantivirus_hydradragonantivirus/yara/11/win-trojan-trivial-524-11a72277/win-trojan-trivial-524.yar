rule Win_Trojan_Trivial_524
{
strings:
	$a0 = { 2a00b44e89f2cd21b802 }


condition:
	$a0
}