rule Win_Trojan_Mini_58
{
strings:
	$a0 = { cd2193b43f5459ba3f01cd21803e3f01917413053f005033c9f7e1b442cd2189f259b440cd21 }


condition:
	$a0
}