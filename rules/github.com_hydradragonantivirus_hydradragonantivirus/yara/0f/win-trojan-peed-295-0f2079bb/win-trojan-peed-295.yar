rule Win_Trojan_Peed_295
{
strings:
	$a0 = { 050016000054e8a000000068247700005981c1505f000081e9dc88ffffba }


condition:
	$a0
}