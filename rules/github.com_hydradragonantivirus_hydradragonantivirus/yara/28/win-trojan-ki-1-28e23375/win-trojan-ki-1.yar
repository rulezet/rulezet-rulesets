rule Win_Trojan_Ki_1
{
strings:
	$a0 = { 1e0680fc0074072ec70638039c9ab82435cd2153061e52 }


condition:
	$a0
}