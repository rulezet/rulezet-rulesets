rule Win_Trojan_Not_2
{
strings:
	$a0 = { ebe15e8be55dc3558bec833ea800207505b80100eb138b1ea800d1e38b460489878402ff06a800 }


condition:
	$a0
}