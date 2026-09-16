rule Win_Trojan_IVP_8
{
strings:
	$a0 = { e2fdba3a02ffd2c353ba2202ffd25bb440b93a01ba0001cd2153ba2202ffd25bc3 }


condition:
	$a0
}