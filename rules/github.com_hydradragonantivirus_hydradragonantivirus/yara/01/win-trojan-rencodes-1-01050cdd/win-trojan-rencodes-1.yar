rule Win_Trojan_Rencodes_1
{
strings:
	$a0 = { 018bfe8d161f018d0e7d0a2bcafcacd0c8aae2fae9a908 }


condition:
	$a0
}