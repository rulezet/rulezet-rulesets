rule Win_Trojan_Mini_60
{
strings:
	$a0 = { b44ecd21b44fcd217233ba9e00b8023dcd2193a19a00ba47018bc805470050b43fcd215880 }


condition:
	$a0
}