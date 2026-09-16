rule Win_Trojan_Flu_1
{
strings:
	$a0 = { 215880c4a6cd213dcaca7474bb0112ba202303da93cd21 }


condition:
	$a0
}