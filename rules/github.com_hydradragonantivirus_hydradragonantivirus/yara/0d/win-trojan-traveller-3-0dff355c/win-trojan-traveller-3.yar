rule Win_Trojan_Traveller_3
{
strings:
	$a0 = { e8db00ba0001b90300b440cd21b80242 }


condition:
	$a0
}