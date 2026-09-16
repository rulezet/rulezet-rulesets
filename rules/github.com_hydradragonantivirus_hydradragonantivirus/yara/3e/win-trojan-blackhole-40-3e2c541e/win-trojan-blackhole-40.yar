rule Win_Trojan_Blackhole_40
{
strings:
	$a0 = { 7472797b70726f746f747970652d313b7d6361746368286261776729 }


condition:
	$a0
}