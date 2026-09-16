rule Win_Trojan_Emanuela_1
{
strings:
	$a0 = { b8ce7bcd213dce7b745db80048bb1f00cd2173128cd8488ed88b1e030083eb20b44acd21ebe4 }


condition:
	$a0
}