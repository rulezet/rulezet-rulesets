rule Win_Trojan_PCBB_9
{
strings:
	$a0 = { fc12744a80fc3e751881fb01c07512b80600bb0dd0 }


condition:
	$a0
}