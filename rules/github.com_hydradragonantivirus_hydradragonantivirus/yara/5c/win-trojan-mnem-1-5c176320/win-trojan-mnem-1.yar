rule Win_Trojan_MNem_1
{
strings:
	$a0 = { b8000050b92e0290e800005b83c3149083c4022e290783c3020500004975f4 }


condition:
	$a0
}