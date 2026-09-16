rule Win_Trojan_Small_4173
{
strings:
	$a0 = { e817000000be3f??b20081f62636 }


condition:
	$a0
}