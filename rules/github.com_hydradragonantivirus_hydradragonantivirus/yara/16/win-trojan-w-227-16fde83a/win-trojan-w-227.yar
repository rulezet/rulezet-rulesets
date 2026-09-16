rule Win_Trojan_W_227
{
strings:
	$a0 = { dc6700ac486500847dd68d571a13801768b85f4b1cb037f6ac124037bc230fb412aefd849cb0b70168006c630b36d7fd }


condition:
	$a0
}