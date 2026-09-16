rule Win_Trojan_Gen_73
{
strings:
	$a0 = { c2c500b44eeb02b44fcd217303e98600 }


condition:
	$a0
}