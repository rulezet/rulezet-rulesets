rule Win_Trojan_SillyC_73
{
strings:
	$a0 = { cd21b80242e826008d960301b440b9b200cd21b80157b1332e8b168800cd212ec70680000000b4 }


condition:
	$a0
}