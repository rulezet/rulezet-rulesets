rule Win_Trojan_Mini_77
{
strings:
	$a0 = { bb0f00b44acd218cc280c6108ec25256b426cd218bfebe5d0156b5fef3a4495fba5701b44eeb02b44fcd217227ba9e00b8023dcd21938bd7b43fcd21055d0080 }


condition:
	$a0
}