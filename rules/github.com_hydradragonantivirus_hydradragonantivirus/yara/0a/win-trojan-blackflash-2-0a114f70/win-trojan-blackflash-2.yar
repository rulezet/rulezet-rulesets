rule Win_Trojan_BlackFlash_2
{
strings:
	$a0 = { c33e00b9ec028a07e80800880743e2f61feb12505351b8 }


condition:
	$a0
}