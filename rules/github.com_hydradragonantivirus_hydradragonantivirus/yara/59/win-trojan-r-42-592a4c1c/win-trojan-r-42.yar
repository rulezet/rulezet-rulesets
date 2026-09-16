rule Win_Trojan_R_42
{
strings:
	$a0 = { b93003cd21b8004233c9cd21b440b90400ba2c03cd21b801572e8b0e22032e8b16200380e1e0 }


condition:
	$a0
}