rule Win_Trojan_IRA_1
{
strings:
	$a0 = { 26040108010000fce80a00bed40103360601ffe600be150103360601b923048a2483c62e908bfe90ac32c4aae2fac3 }


condition:
	$a0
}