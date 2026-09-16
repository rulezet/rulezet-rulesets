rule Win_Trojan_Dune_3
{
strings:
	$a0 = { 5d83ed0381fd00017411bf1e00b9620203fdb000280d300547e2f9 }


condition:
	$a0
}