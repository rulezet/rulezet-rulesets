rule Win_Trojan_PS_26
{
strings:
	$a0 = { cd2180fe08721280fa01720d81f9c9077207b42ccd21 }


condition:
	$a0
}