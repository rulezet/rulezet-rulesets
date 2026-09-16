rule Win_Trojan_Berg_1
{
strings:
	$a0 = { b447be????32d2cd211e06b82135cd2187da061fb80325cd21071fba????e81300 }


condition:
	$a0
}