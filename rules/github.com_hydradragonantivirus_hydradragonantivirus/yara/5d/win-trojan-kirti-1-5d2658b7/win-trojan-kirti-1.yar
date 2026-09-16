rule Win_Trojan_Kirti_1
{
strings:
	$a0 = { c700018b0e08018a0481fe400172042ac4880428054647 }


condition:
	$a0
}