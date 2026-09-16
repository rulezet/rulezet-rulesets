rule Win_Trojan_Killer_3
{
strings:
	$a0 = { 33c08ec0bf0505be3404b96900f3a67503e98803bf0505be3404b96900f3a40e07b44abb0010cd21bbc403d1ebd1eb }


condition:
	$a0
}