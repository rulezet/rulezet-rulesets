rule Win_Trojan_Hip_2
{
strings:
	$a0 = { 99cd21b4405a5981c1d100cd21b43ecd21b44feb8621486950211f07bf0001578bf781c6d1 }


condition:
	$a0
}