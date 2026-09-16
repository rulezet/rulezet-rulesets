rule Win_Trojan_Sorry_1
{
strings:
	$a0 = { 1e61002e8c0663000e1fba8801b82125 }


condition:
	$a0
}