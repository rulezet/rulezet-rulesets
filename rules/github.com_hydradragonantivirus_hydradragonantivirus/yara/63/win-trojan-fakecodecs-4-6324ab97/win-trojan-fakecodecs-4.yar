rule Win_Trojan_Fakecodecs_4
{
strings:
	$a0 = { 89df6683e8a78b575c536683c963525666 }

	$a1 = { c0336c44715564693244f152 }


condition:
	$a0 and $a1
}