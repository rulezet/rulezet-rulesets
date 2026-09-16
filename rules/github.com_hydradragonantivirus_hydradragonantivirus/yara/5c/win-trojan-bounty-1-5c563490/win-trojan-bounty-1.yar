rule Win_Trojan_Bounty_1
{
strings:
	$a0 = { 89005030e488262800cd1380262300808b1e2600bd0002e8ea008b1e26004331c08ec0bd007ce8 }


condition:
	$a0
}