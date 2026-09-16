rule Win_Trojan_Philis_120
{
strings:
	$a0 = { 53565e56575fc1cb45c1c34503f3545e5e81c1dd7618205481e9dd76 }


condition:
	$a0
}