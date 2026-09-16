rule Win_Trojan_LAVI_4
{
strings:
	$a0 = { 01b9060481e91601268a02345e26880246e2f5c3 }


condition:
	$a0
}