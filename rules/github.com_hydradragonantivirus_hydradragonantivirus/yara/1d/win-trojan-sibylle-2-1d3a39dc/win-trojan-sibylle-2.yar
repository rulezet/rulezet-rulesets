rule Win_Trojan_Sibylle_2
{
strings:
	$a0 = { cd210bd274bc80fa3273e188166403b800f08b16fc02 }


condition:
	$a0
}