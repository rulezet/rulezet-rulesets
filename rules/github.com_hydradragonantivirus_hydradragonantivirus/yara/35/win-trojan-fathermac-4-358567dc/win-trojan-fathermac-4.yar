rule Win_Trojan_FatherMac_4
{
strings:
	$a0 = { 01b9320481e91601268a02342326880246e2f5c3 }


condition:
	$a0
}