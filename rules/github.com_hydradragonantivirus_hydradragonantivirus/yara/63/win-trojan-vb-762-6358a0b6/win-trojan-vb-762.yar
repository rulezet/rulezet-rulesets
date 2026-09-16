rule Win_Trojan_VB_762
{
strings:
	$a0 = { 6275747369 }

	$a1 = { 5c000000080000002e006500780065 }

	$a2 = { 5c00780064002e006200610074 }

	$a3 = { 4b72697469736368 }


condition:
	$a0 and $a1 and $a2 and $a3
}