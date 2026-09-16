rule Win_Trojan_ViruSoft_1
{
strings:
	$a0 = { 4233c9e84c00b440b98f0233d2e842005ab8004233c9e83900b440b90500ba5202e82e005a59 }


condition:
	$a0
}