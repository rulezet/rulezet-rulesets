rule Win_Trojan_Soulfly_2
{
strings:
	$a0 = { d807b940008bd6e8050072023bc1c3b43fe9a4fee896feb1188bd6b440e998fe3c6172063c7a77 }


condition:
	$a0
}