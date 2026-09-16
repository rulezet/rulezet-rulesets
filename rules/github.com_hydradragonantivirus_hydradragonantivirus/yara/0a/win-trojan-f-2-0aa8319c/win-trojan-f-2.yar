rule Win_Trojan_F_2
{
strings:
	$a0 = { 33fff3a5068cc633c08ec026a18400268b0e86000726 }


condition:
	$a0
}