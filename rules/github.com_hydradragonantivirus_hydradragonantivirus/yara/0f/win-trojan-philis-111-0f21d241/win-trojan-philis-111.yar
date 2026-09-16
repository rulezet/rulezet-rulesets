rule Win_Trojan_Philis_111
{
strings:
	$a0 = { 81eabd77915e81c2bd77915e895424fc528bd48b1283c40481e82b70291d81c02b7029 }


condition:
	$a0
}