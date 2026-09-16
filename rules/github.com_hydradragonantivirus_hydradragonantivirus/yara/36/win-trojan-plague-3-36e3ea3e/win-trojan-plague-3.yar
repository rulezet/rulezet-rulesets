rule Win_Trojan_Plague_3
{
strings:
	$a0 = { 273226060188274381fb83037ef1eb }


condition:
	$a0
}