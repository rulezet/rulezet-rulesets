rule Win_Trojan_Damage_1
{
strings:
	$a0 = { 21b8023dcd21722693b80057cd21721a }


condition:
	$a0
}