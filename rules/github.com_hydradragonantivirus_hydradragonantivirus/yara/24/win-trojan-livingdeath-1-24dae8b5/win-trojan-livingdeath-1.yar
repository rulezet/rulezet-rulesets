rule Win_Trojan_LivingDeath_1
{
strings:
	$a0 = { fc04cd08391efe045a7505a1fc04eb554a521f8b1e030081eb1201b44acd21b80058cd2150bb }


condition:
	$a0
}