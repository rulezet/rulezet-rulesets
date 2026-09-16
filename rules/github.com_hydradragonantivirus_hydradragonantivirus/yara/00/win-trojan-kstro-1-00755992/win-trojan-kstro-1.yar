rule Win_Trojan_Kstro_1
{
strings:
	$a0 = { 54028a4414345c88441233d2b93405b440cd21b000e82800ba3b05b91800b440cd21803e600501 }


condition:
	$a0
}