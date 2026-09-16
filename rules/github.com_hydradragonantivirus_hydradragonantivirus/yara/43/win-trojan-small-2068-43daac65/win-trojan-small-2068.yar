rule Win_Trojan_Small_2068
{
strings:
	$a0 = { 80cc0c5589e580f62081ec9400000081ecfc0c000080c93b89e3 }


condition:
	$a0
}