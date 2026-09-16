rule Win_Trojan_Tangle_2
{
strings:
	$a0 = { 334975fd4975fd4975fde86e01eafa56578b3e0101e86301ea81c731018bf7b94c01b4 }


condition:
	$a0
}