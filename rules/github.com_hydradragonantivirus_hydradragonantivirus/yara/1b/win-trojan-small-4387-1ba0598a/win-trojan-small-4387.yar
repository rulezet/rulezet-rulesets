rule Win_Trojan_Small_4387
{
strings:
	$a0 = { 31db8d837b30f9f905854547065068fc }


condition:
	$a0
}