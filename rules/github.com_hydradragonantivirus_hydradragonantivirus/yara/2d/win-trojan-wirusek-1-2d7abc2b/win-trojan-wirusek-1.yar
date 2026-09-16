rule Win_Trojan_Wirusek_1
{
strings:
	$a0 = { b435b021cd211f1ebf12008c05bf1000891dba9406b425 }


condition:
	$a0
}