rule Win_Trojan_Gen_43
{
strings:
	$a0 = { e1ffe8d1ff079c33c08ec026ff1e04 }


condition:
	$a0
}