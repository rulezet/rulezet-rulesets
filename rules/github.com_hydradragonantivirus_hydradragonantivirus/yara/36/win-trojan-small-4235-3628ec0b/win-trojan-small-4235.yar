rule Win_Trojan_Small_4235
{
strings:
	$a0 = { 81c04945a0195481e84945a0 }


condition:
	$a0
}