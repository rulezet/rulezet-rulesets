rule Win_Trojan_Small_1610
{
strings:
	$a0 = { 682010400056ff150c10400085c074086a016a00ffd05959 }


condition:
	$a0
}