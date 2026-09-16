rule Win_Trojan_HKill_1
{
strings:
	$a0 = { 5b8a24535b2004535bf7d0535b22c4535b87c9525a0804535b87c9525a46535be2d5 }


condition:
	$a0
}