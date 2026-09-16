rule Win_Trojan_Chameleon_9
{
strings:
	$a0 = { bf2711310d902bda33d12bd82bd9310590404b47e2ed }


condition:
	$a0
}