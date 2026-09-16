rule Win_Trojan_Boot431_1
{
strings:
	$a0 = { 8becc7460200005d1fa03f0451b104d2e0593c0074050e1fe808001f589d2eff2ec500 }


condition:
	$a0
}