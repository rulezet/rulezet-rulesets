rule Win_Trojan_E_9
{
strings:
	$a0 = { d42fed992c23c4d475b5fb0805fffe672eafe16e3b6d2eaea15806070d7dd42fedfb08237ed4312d }


condition:
	$a0
}