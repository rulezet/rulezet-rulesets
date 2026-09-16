rule Win_Trojan_Trojan_204
{
strings:
	$a0 = { e90000e2feb80325ba5c01cd21891e22068c062406ba5c01b425cd }


condition:
	$a0
}