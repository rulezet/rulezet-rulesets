rule Win_Trojan_Small_196
{
strings:
	$a0 = { 8bcacd212d0300894473908bd6b440b97300cd21b80042998b }


condition:
	$a0
}