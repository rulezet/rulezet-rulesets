rule Win_Trojan_Breeder_2
{
strings:
	$a0 = { 018bfe8d161f018d0e2f0e2bcafcacd0c8aae2fae9 }


condition:
	$a0
}