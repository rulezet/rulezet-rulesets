rule Win_Trojan_Crypted_27
{
strings:
	$a0 = { 558bec8bff83ec1ce872ffffffc745ec0530000068647af41a8f45f4c745f8abcf4a072945ecb901000000918d15b390420092c1e10f2bc1c1e20d250000ffff }


condition:
	$a0
}