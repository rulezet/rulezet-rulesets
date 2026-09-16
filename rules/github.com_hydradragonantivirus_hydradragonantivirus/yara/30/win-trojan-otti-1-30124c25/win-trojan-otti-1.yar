rule Win_Trojan_Otti_1
{
strings:
	$a0 = { c6db0381fedb03743289f381c38e0481ebdb0333d28ec226891e0c00 }


condition:
	$a0
}