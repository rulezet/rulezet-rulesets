rule Win_Trojan_TheThing_4
{
strings:
	$a0 = { 46fceb0433d233c05f5ec9c300558bec565733d28bda8a877808b4003b460475048bc2eb094283fa067ce9b8ffff5f5e5dc3558bec83ec025657ff7604e8cdff }


condition:
	$a0
}