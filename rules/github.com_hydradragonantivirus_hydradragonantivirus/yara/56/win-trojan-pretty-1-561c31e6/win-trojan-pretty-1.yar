rule Win_Trojan_Pretty_1
{
strings:
	$a0 = { 8ec0b90100b600803efd7d80907502b026e8a200c3b80103eb0490b80102 }


condition:
	$a0
}