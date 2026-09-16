rule Win_Trojan_Evul_2
{
strings:
	$a0 = { 01b440b90801cd2190b801578b16b8018b0eba01cd21 }


condition:
	$a0
}