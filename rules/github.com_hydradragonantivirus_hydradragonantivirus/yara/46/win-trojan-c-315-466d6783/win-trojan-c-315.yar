rule Win_Trojan_C_315
{
strings:
	$a0 = { c500ca000600df00e9000600fc }

	$a1 = { 46697265466f7820537465616c65722e657865 }


condition:
	$a0 and $a1
}