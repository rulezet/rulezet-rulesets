rule Win_Trojan_Coconut_3
{
strings:
	$a0 = { 83be930800740fad2bc133c1d3c0ab3eff8e9308ebe9c3 }


condition:
	$a0
}