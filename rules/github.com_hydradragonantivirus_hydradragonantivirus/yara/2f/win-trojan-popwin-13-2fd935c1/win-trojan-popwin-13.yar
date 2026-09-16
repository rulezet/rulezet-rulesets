rule Win_Trojan_Popwin_13
{
strings:
	$a0 = { 6b6f77696e496542000000000000000000000000 }

	$a1 = { 6572796e782e636e2f002e444c }


condition:
	$a0 and $a1
}