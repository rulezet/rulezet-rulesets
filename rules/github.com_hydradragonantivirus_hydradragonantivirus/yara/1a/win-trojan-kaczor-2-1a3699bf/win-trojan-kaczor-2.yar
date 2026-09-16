rule Win_Trojan_Kaczor_2
{
strings:
	$a0 = { 3500042eff062200902e813e2200581175eb90 }


condition:
	$a0
}