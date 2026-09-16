rule Win_Trojan_VB_988
{
strings:
	$a0 = { 62006f006e00690074006f006f }

	$a1 = { 6f00700065006e }

	$a2 = { 43003a005c }

	$a3 = { 5c00410044004d0049004e0024 }


condition:
	$a0 and $a1 and $a2 and $a3
}