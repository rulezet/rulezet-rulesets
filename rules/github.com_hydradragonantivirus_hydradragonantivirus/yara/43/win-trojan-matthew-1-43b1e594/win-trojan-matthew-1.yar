rule Win_Trojan_Matthew_1
{
strings:
	$a0 = { c08ec026803ebc0100077503e95001e90d018cc0fa8ed0 }


condition:
	$a0
}