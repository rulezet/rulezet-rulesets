rule Win_Trojan_Blackhole_36
{
strings:
	$a0 = { 70726f746f747970653b7d636174636828623433676473 }


condition:
	$a0
}