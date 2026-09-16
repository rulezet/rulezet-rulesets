rule Win_Trojan_BestWishes_2
{
strings:
	$a0 = { e8b8fe30e45031d2b90100bbca04cd25 }


condition:
	$a0
}