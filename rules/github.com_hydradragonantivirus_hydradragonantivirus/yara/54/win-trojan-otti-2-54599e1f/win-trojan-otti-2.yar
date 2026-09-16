rule Win_Trojan_Otti_2
{
strings:
	$a0 = { 8ec226891e0c000e5a2689160e008a67028b5c0630e330e781c33f01b9930481e93f01cce2fd }


condition:
	$a0
}