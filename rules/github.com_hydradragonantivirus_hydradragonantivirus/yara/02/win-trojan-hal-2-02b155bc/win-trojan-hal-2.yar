rule Win_Trojan_Hal_2
{
strings:
	$a0 = { 048b471333ff33f648894713505bb105fec1d3e35307 }


condition:
	$a0
}