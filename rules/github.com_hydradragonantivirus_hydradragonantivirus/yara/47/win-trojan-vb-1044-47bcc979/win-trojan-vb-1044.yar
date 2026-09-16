rule Win_Trojan_VB_1044
{
strings:
	$a0 = { 68041e4000e8eeffffff0000000000003000000038 }

	$a1 = { 57656242726f7773657231 }

	$a2 = { 6f006e0063006c00690063006b }

	$a3 = { 7300720063 }


condition:
	$a0 and $a1 and $a2 and $a3
}