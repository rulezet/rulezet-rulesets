rule Win_Trojan_Delf_2285
{
strings:
	$a0 = { 558becb9180000006a006a004975f951b84c724100e80600452433 }

	$a1 = { 5c5f746e6e6977 }


condition:
	$a0 and $a1
}