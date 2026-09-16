rule Win_Trojan_VGEN_114
{
strings:
	$a0 = { 501e068cd88bd00e1fe800005e83ee0e8bc80510008bd8034457035c5f50ff745953ff745deb755b204d6972726f }


condition:
	$a0
}