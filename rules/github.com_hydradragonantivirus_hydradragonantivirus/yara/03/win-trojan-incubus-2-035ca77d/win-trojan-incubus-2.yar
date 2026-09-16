rule Win_Trojan_Incubus_2
{
strings:
	$a0 = { 33c08ed0bc007c1607bb007eb80102b91100ba8000cd13ffe3 }


condition:
	$a0
}