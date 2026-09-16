rule Win_Trojan_Dementia_2
{
strings:
	$a0 = { 5e81c66a108bfeb92908fdba962a0e0e1f07ad33c2abeb00e2f8 }


condition:
	$a0
}