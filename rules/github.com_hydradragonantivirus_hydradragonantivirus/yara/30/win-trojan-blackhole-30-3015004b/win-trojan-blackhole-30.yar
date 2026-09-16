rule Win_Trojan_Blackhole_30
{
strings:
	$a0 = { 7d7472797b70726f746f747970653b7d636174636828 }


condition:
	$a0
}