rule Win_Trojan_Buzus_27
{
strings:
	$a0 = { 558bec6aff689820400068241d400064a1000000005064 }


condition:
	$a0
}