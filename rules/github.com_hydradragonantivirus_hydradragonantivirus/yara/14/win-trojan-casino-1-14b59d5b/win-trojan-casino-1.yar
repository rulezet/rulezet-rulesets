rule Win_Trojan_Casino_1
{
strings:
	$a0 = { 10baff1f9090904a75faa00d063a0610067410b219a0 }


condition:
	$a0
}