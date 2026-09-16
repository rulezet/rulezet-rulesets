rule Win_Trojan_Sailor_9
{
strings:
	$a0 = { e800005d81ed03000e1fbf280003fdb8170757eb06bfd204b8c204518bc8813500004747e2f859c3 }


condition:
	$a0
}