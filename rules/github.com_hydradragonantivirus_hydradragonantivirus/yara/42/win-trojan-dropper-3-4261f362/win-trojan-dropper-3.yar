rule Win_Trojan_Dropper_3
{
strings:
	$a0 = { 04eb04b54fb10dba0001b80602cd13 }


condition:
	$a0
}