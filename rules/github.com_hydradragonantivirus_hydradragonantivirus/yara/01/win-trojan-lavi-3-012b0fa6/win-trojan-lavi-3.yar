rule Win_Trojan_LAVI_3
{
strings:
	$a0 = { b9030481e91601268a02345d26880246e2f5c3 }


condition:
	$a0
}