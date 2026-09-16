rule Win_Trojan_Dialer_942
{
strings:
	$a0 = { 558becb9230000006a006a004975f9b800009328 }

	$a1 = { 0074703a2f00[0-12]2f636f6e7400 }


condition:
	$a0 and $a1
}