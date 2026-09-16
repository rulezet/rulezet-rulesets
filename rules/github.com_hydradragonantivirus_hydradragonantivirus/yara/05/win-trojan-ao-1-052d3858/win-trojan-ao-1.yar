rule Win_Trojan_AO_1
{
strings:
	$a0 = { 01722e3d70fb77292d03002ea30e01b440b9100390ba0001cd217215b8004233c933d2cd2172 }


condition:
	$a0
}