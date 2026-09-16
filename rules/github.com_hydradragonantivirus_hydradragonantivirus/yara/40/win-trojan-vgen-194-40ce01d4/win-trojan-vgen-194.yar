rule Win_Trojan_VGEN_194
{
strings:
	$a0 = { bd04008db6af03ffd6acaa214335068a591706aa581702926f1774e352e352ef038204173ac20ef8caa4462028388c38 }


condition:
	$a0
}