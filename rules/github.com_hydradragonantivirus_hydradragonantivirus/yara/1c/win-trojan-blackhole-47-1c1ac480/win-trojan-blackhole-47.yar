rule Win_Trojan_Blackhole_47
{
strings:
	$a0 = { 6f222b22746f7479706522293b7d6361746368287a7863297b653d6576616c3b }


condition:
	$a0
}