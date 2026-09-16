rule Win_Trojan_BigV_1
{
strings:
	$a0 = { 02000060fab98c055e83c611812c300c46e2f9 }


condition:
	$a0
}