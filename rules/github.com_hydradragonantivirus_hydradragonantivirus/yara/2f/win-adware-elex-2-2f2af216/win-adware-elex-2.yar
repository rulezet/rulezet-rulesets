rule Win_Adware_ELEX_2
{
strings:
	$a0 = { 5c00530046004b002e0069006e006900000000007400300030006c }


condition:
	$a0
}