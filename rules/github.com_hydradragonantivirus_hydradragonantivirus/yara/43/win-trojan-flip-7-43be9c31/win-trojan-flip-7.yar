rule Win_Trojan_Flip_7
{
strings:
	$a0 = { 1fb9e885b2a781c1f782eb07058305830583050097250843eb }


condition:
	$a0
}