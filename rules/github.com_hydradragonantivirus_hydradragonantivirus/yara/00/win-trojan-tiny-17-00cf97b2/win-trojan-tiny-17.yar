rule Win_Trojan_Tiny_17
{
strings:
	$a0 = { cd2193b43f5459ba3f01cd21803e3f01917413053f005033c9f7e1b442cd218bd659b440cd21 }


condition:
	$a0
}