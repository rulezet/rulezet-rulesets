rule Win_Trojan_Chs_3
{
strings:
	$a0 = { 9a0000ed009a0d008b005589e581ec0001b00050bf16221e57b84f00509a5f0bed008dbe00ff1657bf16221e57b80100 }


condition:
	$a0
}