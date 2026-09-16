rule Win_Trojan_Bace_1
{
strings:
	$a0 = { cd2106b44abbffffcd21b44aba180026291602002bdacd21b4488bda4bcd21488ec04026c7 }


condition:
	$a0
}