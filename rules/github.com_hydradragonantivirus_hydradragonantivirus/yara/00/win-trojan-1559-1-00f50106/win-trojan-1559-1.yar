rule Win_Trojan_1559_1
{
strings:
	$a0 = { e8d1ff079c33c08ec026ff1e0400 }


condition:
	$a0
}