rule Win_Trojan_Warrior_2
{
strings:
	$a0 = { c08b1e030083eb508ed8b44acd21eb }


condition:
	$a0
}