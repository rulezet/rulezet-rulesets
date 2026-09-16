rule Win_Trojan_Keydat_1
{
strings:
	$a0 = { 87063c04a3dd00b440b92c0433d2cd21b8004233c933d2cd21b440b91800ba2c04cd21b801 }


condition:
	$a0
}