rule Win_Trojan_Lawine_3
{
strings:
	$a0 = { 8bd866b9b2080000bb[1-10]2e8037??f943fce2f7 }


condition:
	$a0
}