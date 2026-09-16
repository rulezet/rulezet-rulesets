rule Win_Trojan_P1_2
{
strings:
	$a0 = { 1f8bfb33d2b94203513357224343497df85831552247474879f8 }


condition:
	$a0
}