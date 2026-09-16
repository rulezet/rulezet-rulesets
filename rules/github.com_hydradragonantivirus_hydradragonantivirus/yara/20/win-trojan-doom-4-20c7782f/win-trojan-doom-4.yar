rule Win_Trojan_Doom_4
{
strings:
	$a0 = { 803e09014574052e033e03012e300547 }


condition:
	$a0
}