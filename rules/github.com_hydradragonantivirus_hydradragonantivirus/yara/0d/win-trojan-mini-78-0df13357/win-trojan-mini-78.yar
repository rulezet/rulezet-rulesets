rule Win_Trojan_Mini_78
{
strings:
	$a0 = { b44acd218cc280c6108ec25256b426cd2189f7be5d0156b5fef3a4495fba5701b44eeb02b44fcd217227ba9e00 }


condition:
	$a0
}