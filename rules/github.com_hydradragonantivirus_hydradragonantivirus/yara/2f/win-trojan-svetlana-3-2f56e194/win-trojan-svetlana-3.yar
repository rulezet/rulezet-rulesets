rule Win_Trojan_Svetlana_3
{
strings:
	$a0 = { b440e8dafd72253d520d752033c933d2b80042e8c9fd7214ba260db440b91800e8bcfd7207 }


condition:
	$a0
}