rule Win_Trojan_AntiWin_1
{
strings:
	$a0 = { cd21b440b91c000e1fba4c02cd215361605b680157582e8b0e46022e8b164802cd21b43ecd21 }


condition:
	$a0
}