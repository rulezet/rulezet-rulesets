rule Win_Trojan_Agent_35513
{
strings:
	$a0 = { 5589e583ec3281e0ed00000083e8712b0521 }


condition:
	$a0
}