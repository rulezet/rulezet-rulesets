rule Win_Trojan_Vienna_29
{
strings:
	$a0 = { 0bd275422d030089450489fab91a0029cf83c70205030103c18905b44089d729cab90902cd21 }


condition:
	$a0
}