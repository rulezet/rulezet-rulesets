rule Win_Trojan_Blackhole_45
{
strings:
	$a0 = { 797b322b70726f746f747970653b7d63617463682876297b783d313b7d }


condition:
	$a0
}