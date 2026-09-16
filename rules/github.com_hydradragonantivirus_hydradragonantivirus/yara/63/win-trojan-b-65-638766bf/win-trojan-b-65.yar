rule Win_Trojan_B_65
{
strings:
	$a0 = { 30e488262800cd1380262300808b1e2600bd0002e85cff8b1e26004331c08ec0bd007ce84dffea }


condition:
	$a0
}