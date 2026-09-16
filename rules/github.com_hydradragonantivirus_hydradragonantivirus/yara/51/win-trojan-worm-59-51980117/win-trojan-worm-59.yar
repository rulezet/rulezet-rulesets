rule Win_Trojan_Worm_59
{
strings:
	$a0 = { 74faffff3c0175076a00e819bcffffe8ccfbffff3c0175076a00e809bcffffe82cfaffff3c0175076a00e8f9bbffff }


condition:
	$a0
}