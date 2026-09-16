rule Win_Trojan_Meac_1
{
strings:
	$a0 = { 5c4d69634e735c7069642e696e69 }


condition:
	$a0
}