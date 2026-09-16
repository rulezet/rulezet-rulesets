rule Win_Trojan_BlackFlash_1
{
strings:
	$a0 = { 3e00b9ed028a07e80800880743e2f61feb12505351b8 }


condition:
	$a0
}