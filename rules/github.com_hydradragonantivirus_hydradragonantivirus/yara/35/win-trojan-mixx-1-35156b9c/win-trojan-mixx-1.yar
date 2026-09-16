rule Win_Trojan_Mixx_1
{
strings:
	$a0 = { 8b1efa01b93a0233d2cd2172569090908b1efa01b800 }


condition:
	$a0
}