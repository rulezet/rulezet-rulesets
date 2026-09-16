rule Win_Trojan_Crypt_268
{
strings:
	$a0 = { c1d60ac0d10481ce471698aad2c780dcaa2ae5fec113d7d2d212c180dfb06648 }


condition:
	$a0
}