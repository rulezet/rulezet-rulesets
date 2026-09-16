rule Win_Trojan_Blackhole_33
{
strings:
	$a0 = { 3b7d636174636828717767297b }


condition:
	$a0
}