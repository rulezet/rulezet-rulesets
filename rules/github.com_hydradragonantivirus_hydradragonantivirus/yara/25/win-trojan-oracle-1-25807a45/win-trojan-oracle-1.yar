rule Win_Trojan_Oracle_1
{
strings:
	$a0 = { 1c00bae803cd215a59b80042cd2133c9b440cd215a59b80157cd21b43e9c2eff1ed600 }


condition:
	$a0
}