rule Win_Trojan_VB_1722
{
strings:
	$a0 = { 5083006b6f6166656f6570000000006c }


condition:
	$a0
}