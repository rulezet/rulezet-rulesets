rule Win_Trojan_Renegy_1
{
strings:
	$a0 = { 202020207468697346696c65203d206c6f636174696f6e2e70 }


condition:
	$a0
}