rule Win_Trojan_Small_4479
{
strings:
	$a0 = { ff74241c588d80??????045068623435 }


condition:
	$a0
}