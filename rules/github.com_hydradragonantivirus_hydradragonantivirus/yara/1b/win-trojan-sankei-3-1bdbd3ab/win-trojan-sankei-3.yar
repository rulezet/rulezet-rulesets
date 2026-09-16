rule Win_Trojan_Sankei_3
{
strings:
	$a0 = { e8000000005d81ed051040008b1c2481e30000ffff }


condition:
	$a0
}