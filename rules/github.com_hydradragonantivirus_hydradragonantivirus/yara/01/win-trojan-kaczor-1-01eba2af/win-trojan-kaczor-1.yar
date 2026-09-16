rule Win_Trojan_Kaczor_1
{
strings:
	$a0 = { 2ec0062600??2e83061300??2e813e1300491175eb90 }


condition:
	$a0
}