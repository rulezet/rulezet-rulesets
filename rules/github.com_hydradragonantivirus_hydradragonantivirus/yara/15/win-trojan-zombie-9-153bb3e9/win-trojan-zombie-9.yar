rule Win_Trojan_Zombie_9
{
strings:
	$a0 = { c208005589e51eb4408b5e0ac556068b4e04cd211fc9c208005589e5b800428b5e088b4e068b56 }


condition:
	$a0
}