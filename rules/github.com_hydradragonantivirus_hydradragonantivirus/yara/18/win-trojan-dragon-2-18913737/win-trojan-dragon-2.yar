rule Win_Trojan_Dragon_2
{
strings:
	$a0 = { 742580fc4f751db42fcd21061f8d571eb000b90d00 }


condition:
	$a0
}