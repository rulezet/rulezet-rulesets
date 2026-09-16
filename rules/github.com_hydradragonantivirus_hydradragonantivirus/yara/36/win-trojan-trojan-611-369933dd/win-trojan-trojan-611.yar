rule Win_Trojan_Trojan_611
{
strings:
	$a0 = { b43b[0-8]cd21 }

	$a1 = { 2e2e00[0-250]2a2e434f4d00 }


condition:
	$a0 and $a1
}