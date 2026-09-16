rule Win_Trojan_Bancos_707
{
strings:
	$a0 = { c47ddf5170653072a1936b7d7fec5e98ef69a69ad131f16659f503ea2dd40e4386d89d876b23dae043a3675ed82b39a1a7dddd284dd86674f05bfea026415c9225 }


condition:
	$a0
}