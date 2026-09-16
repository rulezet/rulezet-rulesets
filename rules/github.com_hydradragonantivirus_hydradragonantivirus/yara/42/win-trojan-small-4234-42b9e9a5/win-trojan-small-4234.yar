rule Win_Trojan_Small_4234
{
strings:
	$a0 = { e8140000008b4c240481e1000000 }


condition:
	$a0
}