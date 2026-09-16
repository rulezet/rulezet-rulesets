rule Win_Trojan_Delf_2266
{
strings:
	$a0 = { 558becb90e0000006a006a004975f95356 }

	$a1 = { 4578706c4f7265722e657865 }

	$a2 = { 5a7338446e507a7a }


condition:
	$a0 and $a1 and $a2
}