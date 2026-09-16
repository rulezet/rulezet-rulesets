rule Win_Trojan_MMAND_1
{
strings:
	$a0 = { cd213dcd127403eb6490803e9400ff741406ff3695 }


condition:
	$a0
}