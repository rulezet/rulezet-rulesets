rule Win_Trojan_Mannequin_2
{
strings:
	$a0 = { 813e670456441f7531581f072e81beea024d5a7413be }


condition:
	$a0
}