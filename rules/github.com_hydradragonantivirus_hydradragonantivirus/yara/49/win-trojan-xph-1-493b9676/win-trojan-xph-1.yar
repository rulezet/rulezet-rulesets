rule Win_Trojan_XPh_1
{
strings:
	$a0 = { 740580fc3d756e9c505351521e065756558bfa4774 }


condition:
	$a0
}