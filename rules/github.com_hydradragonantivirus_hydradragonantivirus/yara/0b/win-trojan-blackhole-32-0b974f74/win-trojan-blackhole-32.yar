rule Win_Trojan_Blackhole_32
{
strings:
	$a0 = { 7b61766173763d70726f746f747970653b7d6361746368287a29 }


condition:
	$a0
}