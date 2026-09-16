rule Win_Trojan_PS_2
{
strings:
	$a0 = { e800005d81ed03012ec686????00b82435cd210653b82425bac701cd218d96????b44ee8 }


condition:
	$a0
}