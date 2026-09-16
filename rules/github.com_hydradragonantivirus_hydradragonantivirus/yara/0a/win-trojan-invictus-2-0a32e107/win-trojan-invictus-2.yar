rule Win_Trojan_Invictus_2
{
strings:
	$a0 = { f8b92b0be3bffdff095c494e5649435455532e444c4c4efcacaae2fc8d45146edf0e7df16a02df6833f2550489856c1cce }


condition:
	$a0
}