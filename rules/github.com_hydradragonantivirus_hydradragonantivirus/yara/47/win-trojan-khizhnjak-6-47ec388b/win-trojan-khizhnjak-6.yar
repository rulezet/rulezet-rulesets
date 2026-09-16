rule Win_Trojan_Khizhnjak_6
{
strings:
	$a0 = { 0f04b440cd21722733c933d28b1e0f0432c0b442cd217217ba1104b903008b1e0f04b440cd21 }


condition:
	$a0
}