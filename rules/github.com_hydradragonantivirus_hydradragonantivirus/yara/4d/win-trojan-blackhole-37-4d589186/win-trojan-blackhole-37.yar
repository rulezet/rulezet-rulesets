rule Win_Trojan_Blackhole_37
{
strings:
	$a0 = { 70726f746f747970653b7d6361746368286473646829 }


condition:
	$a0
}