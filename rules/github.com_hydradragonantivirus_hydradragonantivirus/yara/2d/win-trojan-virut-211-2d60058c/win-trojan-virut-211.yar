rule Win_Trojan_Virut_211
{
strings:
	$a0 = { e81b0000005dc30f31c353b9????00008bda66311003d38d4002e2f65bc3 }


condition:
	$a0
}