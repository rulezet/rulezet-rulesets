rule Win_Trojan_Scity_2
{
strings:
	$a0 = { c604744fb4ffbbffffcd210bdb74441ebf02008cd8488e }


condition:
	$a0
}