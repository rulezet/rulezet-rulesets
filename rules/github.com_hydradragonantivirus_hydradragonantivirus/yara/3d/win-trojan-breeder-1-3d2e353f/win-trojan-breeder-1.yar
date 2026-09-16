rule Win_Trojan_Breeder_1
{
strings:
	$a0 = { 018bfe8d161f018d0e2f0e2bcafcacd0c8aae2fae9480c }


condition:
	$a0
}