rule Win_Trojan_Virut_209
{
strings:
	$a0 = { e81b0000005dc30f31c353b9970c00008bda66311003d38d4002e2f65bc3 }


condition:
	$a0
}