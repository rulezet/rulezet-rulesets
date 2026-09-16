rule Win_Trojan_Blackhole_41
{
strings:
	$a0 = { 7b70726f746f747970652d353b7d636174636828717129 }


condition:
	$a0
}