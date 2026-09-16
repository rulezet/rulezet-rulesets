rule Win_Trojan_VGEN_5
{
strings:
	$a0 = { ba2801cd21b81335cd21891e677c8c06697c8cd805c0078ed8baca00b81325cd21ba0082cd270d0a554e49464f52 }


condition:
	$a0
}