rule Win_Trojan_Peed_247
{
strings:
	$a0 = { 8bf333db33ef33f1480f8305000000c1d3a6f7db33c5f2bf526c }


condition:
	$a0
}