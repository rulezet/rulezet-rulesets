rule Win_Trojan_RSY_1
{
strings:
	$a0 = { 073e7cfbcd1372febb13040e1f832f028b07b106bb727cd3e0532dc007500705200026a30082a1 }


condition:
	$a0
}