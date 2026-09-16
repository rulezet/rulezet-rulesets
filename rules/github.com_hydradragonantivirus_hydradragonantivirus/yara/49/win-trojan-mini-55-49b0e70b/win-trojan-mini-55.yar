rule Win_Trojan_Mini_55
{
strings:
	$a0 = { 9e005052cd2193b43f5459d1e2cd215a01d0935839444a740acd21939189f2b440cd21b44febd1 }


condition:
	$a0
}