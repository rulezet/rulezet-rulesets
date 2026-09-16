rule Win_Trojan_ZeroHunt_1
{
strings:
	$a0 = { 1eb8023dcd2193b43f33c98ed941ba }


condition:
	$a0
}