rule Win_Trojan_SofiaTerminator_3
{
strings:
	$a0 = { ee031e0e1f898403008bc60526008bf88a840500b9a905300547e2fbeb40 }


condition:
	$a0
}