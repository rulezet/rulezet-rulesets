rule Win_Trojan_Walker_3
{
strings:
	$a0 = { 4b7507b841568ccb9dcf0ac074043c1075402ef606ed }


condition:
	$a0
}