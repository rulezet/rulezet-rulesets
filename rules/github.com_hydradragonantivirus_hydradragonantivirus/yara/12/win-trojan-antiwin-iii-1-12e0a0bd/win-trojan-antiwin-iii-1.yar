rule Win_Trojan_AntiWin_III_1
{
strings:
	$a0 = { 9c505351521e06061e0e1fe800005e81ee1301e83102cf06b800c08ec026a1f07f073d97197514b4098d94cf05cd21 }


condition:
	$a0
}