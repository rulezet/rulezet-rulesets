rule Win_Trojan_Qhost_155
{
strings:
	$a0 = { 3132372e302e302e31206c6f63616c686f7374 }

	$a1 = { 34362e342e3137392e313039 }


condition:
	$a0 and $a1
}